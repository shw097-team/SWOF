"""Journal-integrity envelope: a DETECTION-ONLY digest chain over an EXPORTED event stream.

W2-JOURNAL-INTEGRITY-ASSESSMENT. This module verifies a stream of lifecycle events that has
been exported OUT of HG-KSEOS. It never writes to, reads transactional locks in, or claims
cryptographic protection of the HGK database. It is explicitly NOT a signature: there is no
key management, so it cannot prove authorship - only that an exported stream was not modified
after the manifest was produced.

Each entry's digest binds the chain identity:

    entry_digest = sha256(chain_id | seq | event_id | prev_digest | canonical_json(payload))

so an entry lifted from another chain cannot be spliced in (`CHAIN_ID_MISMATCH`), a mutated
payload shows as `ENTRY_DIGEST_MISMATCH`, a removed/truncated entry as `SEQ_GAP`, a reordered
entry as `PREV_DIGEST_MISMATCH` (the `prev_digest` linkage is checked independently of `seq`),
and a tampered header as `HEADER_MISMATCH`.

The chain genesis is chain-bound (sha256 over the chain id), which is what makes a foreign
splice distinguishable from an in-chain payload edit: a foreign seq-1 entry carries a foreign
genesis and fails as CHAIN_ID_MISMATCH before any digest is recomputed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

GENESIS_DOMAIN = "swof.journal.genesis.v1"

MANIFEST_SCHEMA = "SWOF-JOURNAL-MANIFEST/1"
VERDICT_SCHEMA = "SWOF-JOURNAL-VERDICT/1"
THREAT_SCHEMA = "SWOF-W2-JOURNAL-INTEGRITY-ASSESSMENT/1"

# The header carries no signature and no key management, so it is NOT authoritative: a
# coherent rewrite of both the entries and the header is undetectable without an external
# anchor. The anchor is the retained export manifest (verify_against_manifest).
UNAUTHENTICATED_HEADER_NOTE = (
    "COHERENT_HEADER_AND_ENTRY_REWRITE_UNDETECTABLE_WITHOUT_EXTERNAL_ANCHOR")
MANIFEST_IS_ANCHOR_NOTE = "MANIFEST_IS_THE_EXTERNAL_ANCHOR"


class JournalTamperDetected(Exception):
    """A tamper class was detected while verifying an exported chain."""

    code = "ERR_JOURNAL_TAMPER_DETECTED"

    def __init__(self, message, reason_code, first_broken_seq=None):
        super().__init__(message)
        self.reason_code = reason_code
        self.first_broken_seq = first_broken_seq


@dataclass(frozen=True)
class JournalEntry:
    seq: int
    event_id: str
    payload: dict
    prev_digest: str
    entry_digest: str


def chain_genesis(chain_id):
    """The default genesis digest, bound to the chain id (a foreign chain differs here)."""
    return hashlib.sha256((GENESIS_DOMAIN + "\x00" + str(chain_id)).encode("utf-8")).hexdigest()


def _canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _compute_digest(chain_id, seq, event_id, prev_digest, payload):
    material = "\x00".join([
        str(chain_id),
        str(seq),
        str(event_id),
        str(prev_digest),
        _canonical_payload(payload),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _verdict(intact, checked, reason_code, first_broken_seq, *,
             header_is_authoritative=False, anchor_reason_code=None):
    return {
        "schema": VERDICT_SCHEMA,
        "intact": intact,
        "checked": checked,
        "reason_code": reason_code,
        "first_broken_seq": first_broken_seq,
        "header_is_authoritative": header_is_authoritative,
        "anchor_reason_code": anchor_reason_code,
    }


class DigestChainJournal:
    """An append-only digest chain bound to `chain_id`; verify-only over exports."""

    def __init__(self, chain_id, *, genesis_digest=None):
        if not chain_id:
            raise ValueError("chain_id must be non-empty")
        self.chain_id = chain_id
        self.genesis_digest = (chain_genesis(chain_id) if genesis_digest is None
                               else genesis_digest)
        self.entries = []
        self.header = {
            "chain_id": self.chain_id,
            "genesis_digest": self.genesis_digest,
            "entry_count": 0,
            "final_digest": self.genesis_digest,
        }
        self._final_digest = self.genesis_digest

    def append(self, *, event_id, payload):
        seq = len(self.entries) + 1
        prev_digest = self._final_digest
        entry_digest = _compute_digest(self.chain_id, seq, event_id, prev_digest, payload)
        entry = JournalEntry(
            seq=seq,
            event_id=event_id,
            payload=payload,
            prev_digest=prev_digest,
            entry_digest=entry_digest,
        )
        self.entries.append(entry)
        self._final_digest = entry_digest
        self.header["entry_count"] = len(self.entries)
        self.header["final_digest"] = entry_digest
        return entry

    def _is_deletion_not_reorder(self):
        """True when the surviving seq numbers are strictly increasing but fall short of the
        header's declared count - i.e. entries were removed rather than reordered.

        A deletion or truncation leaves strictly increasing, unique seq numbers (a subsequence
        of the range); a naive swap leaves the full multiset of seq numbers but out of order.
        That difference is what separates SEQ_GAP from PREV_DIGEST_MISMATCH.
        """
        seqs = [entry.seq for entry in self.entries]
        if not seqs:
            return True
        if len(set(seqs)) != len(seqs):
            return False
        if any(seqs[index] >= seqs[index + 1] for index in range(len(seqs) - 1)):
            return False
        declared = self.header.get("entry_count")
        if declared is None:
            return True
        return len(seqs) < declared

    def verify(self):
        """Detect tampering in the current (possibly modified) entry list; raise on break.

        Each tamper class maps to its own reason: a mutated payload to ENTRY_DIGEST_MISMATCH, a
        removed or truncated entry to SEQ_GAP, a reordered entry to PREV_DIGEST_MISMATCH, a
        foreign chain splice to CHAIN_ID_MISMATCH and a tampered header to HEADER_MISMATCH. The
        `prev_digest` linkage is checked independently of `seq`, so a swap that leaves the seq
        numbers a permutation of the range is still caught as a linkage break.
        """
        prev_digest = self.genesis_digest
        deleted = self._is_deletion_not_reorder()

        for index, entry in enumerate(self.entries):
            expected_seq = index + 1
            if entry.seq != expected_seq:
                if deleted:
                    self._fail("SEQ_GAP", expected_seq,
                               "expected seq %d, found %d (entry removed or stream "
                               "truncated)" % (expected_seq, entry.seq))
                self._fail("PREV_DIGEST_MISMATCH", entry.seq,
                           "entry seq %d is out of order at position %d (entries reordered)"
                           % (entry.seq, expected_seq))

            if entry.prev_digest != prev_digest:
                if index == 0:
                    self._fail("CHAIN_ID_MISMATCH", entry.seq,
                               "seq 1 prev_digest %r is not this chain's genesis %r "
                               "(foreign chain splice)" % (entry.prev_digest,
                                                           self.genesis_digest))
                self._fail("PREV_DIGEST_MISMATCH", entry.seq,
                           "entry seq %d prev_digest %r != %r (reordered or spliced entry)"
                           % (entry.seq, entry.prev_digest, prev_digest))

            recomputed = _compute_digest(self.chain_id, entry.seq, entry.event_id,
                                         entry.prev_digest, entry.payload)
            if recomputed != entry.entry_digest:
                self._fail("ENTRY_DIGEST_MISMATCH", entry.seq,
                           "entry seq %d digest %r != recomputed %r (payload or header "
                           "mutation)" % (entry.seq, entry.entry_digest, recomputed))

            prev_digest = entry.entry_digest

        declared_count = self.header.get("entry_count")
        if declared_count is not None and len(self.entries) < declared_count:
            self._fail("SEQ_GAP", len(self.entries) + 1,
                       "header declares %d entries but only %d are present "
                       "(entry removed or stream truncated)"
                       % (declared_count, len(self.entries)))

        if declared_count is not None and len(self.entries) > declared_count:
            self._fail("HEADER_MISMATCH", declared_count + 1,
                       "header declares only %d entries but %d are present "
                       "(header tampered or entries appended)" % (declared_count,
                                                                  len(self.entries)))

        if self.header.get("final_digest", prev_digest) != prev_digest:
            self._fail("HEADER_MISMATCH", len(self.entries),
                       "header final_digest %r != chain final digest %r (header tampering)"
                       % (self.header.get("final_digest"), prev_digest))

        # The entries are internally consistent, but the header is unauthenticated, so this is
        # NOT an authoritative verdict: a coherent header+entry rewrite is undetectable here.
        return _verdict(True, len(self.entries), "INTACT", None,
                        header_is_authoritative=False,
                        anchor_reason_code=UNAUTHENTICATED_HEADER_NOTE)

    def _fail(self, reason_code, first_broken_seq, message):
        exc = JournalTamperDetected(message, reason_code, first_broken_seq)
        exc.verdict = _verdict(False, len(self.entries), reason_code, first_broken_seq,
                               header_is_authoritative=False,
                               anchor_reason_code=UNAUTHENTICATED_HEADER_NOTE)
        raise exc

    def export_manifest(self):
        return {
            "schema": MANIFEST_SCHEMA,
            "chain_id": self.chain_id,
            "genesis_digest": self.genesis_digest,
            "final_digest": self.header.get("final_digest", self._final_digest),
            "entry_count": len(self.entries),
            "entry_digests": [entry.entry_digest for entry in self.entries],
        }

    def verify_against_manifest(self, manifest):
        """AUTHORITATIVE check of this journal against a retained export manifest.

        Unlike `verify()` - whose header is unauthenticated - the manifest is an external
        anchor, so a coherent rewrite of both the entry list and the header is detectable
        here (a truncated stream fails as ENTRY_DIGEST_MISMATCH / a count mismatch).
        """
        manifest = dict(manifest or {})
        declared_chain = manifest.get("chain_id")
        if declared_chain is not None and declared_chain != self.chain_id:
            return _verdict(False, len(self.entries), "CHAIN_ID_MISMATCH", None,
                            header_is_authoritative=True,
                            anchor_reason_code=MANIFEST_IS_ANCHOR_NOTE)
        verdict = self.verify_manifest(manifest, self.entries)
        verdict["header_is_authoritative"] = True
        verdict["anchor_reason_code"] = MANIFEST_IS_ANCHOR_NOTE
        return verdict

    @staticmethod
    def verify_manifest(manifest, entries):
        """Re-check a manifest against a re-exported entry list (a pure function)."""
        entries = list(entries or ())
        chain_id = manifest.get("chain_id")
        checked = len(entries)

        if entries and manifest.get("genesis_digest") != entries[0].prev_digest:
            return _verdict(False, checked, "CHAIN_ID_MISMATCH", entries[0].seq)

        if list(manifest.get("entry_digests", ())) != [e.entry_digest for e in entries]:
            return _verdict(False, checked, "ENTRY_DIGEST_MISMATCH",
                            entries[0].seq if entries else None)

        declared_count = manifest.get("entry_count")
        if declared_count != checked:
            if declared_count is not None and checked < declared_count:
                return _verdict(False, checked, "SEQ_GAP", checked + 1)
            return _verdict(False, checked, "HEADER_MISMATCH", checked + 1)

        prev_digest = manifest.get("genesis_digest")
        for index, entry in enumerate(entries):
            if entry.seq != index + 1:
                return _verdict(False, checked, "SEQ_GAP", index + 1)
            if entry.prev_digest != prev_digest:
                return _verdict(False, checked, "PREV_DIGEST_MISMATCH", entry.seq)
            recomputed = _compute_digest(chain_id, entry.seq, entry.event_id,
                                         entry.prev_digest, entry.payload)
            if recomputed != entry.entry_digest:
                return _verdict(False, checked, "ENTRY_DIGEST_MISMATCH", entry.seq)
            prev_digest = entry.entry_digest

        if manifest.get("final_digest", prev_digest) != prev_digest:
            return _verdict(False, checked, "HEADER_MISMATCH", checked)

        return _verdict(True, checked, "INTACT", None)


def from_lifecycle_rows(rows, *, chain_id="HGK-LIFECYCLE-EXPORT"):
    """Build a chain from raw HGK lifecycle rows WITHOUT writing anything back."""
    journal = DigestChainJournal(chain_id)
    for row in rows or ():
        row = dict(row)
        payload = {
            "rowid": row.get("rowid"),
            "transition_id": row.get("transition_id"),
            "from_state": row.get("from_state"),
            "to_state": row.get("to_state"),
            "created_at": row.get("created_at"),
        }
        journal.append(event_id=str(row.get("transition_id")), payload=payload)
    return journal


def threat_assessment():
    """Explicit, non-negotiable statement of what this envelope does and does NOT give."""
    return {
        "schema": THREAT_SCHEMA,
        "implemented": True,
        "protection_class": "DETECTION_ONLY_NO_KEY_MANAGEMENT",
        "db_level_enforcement_claimed": False,
        "writes_to_hgk": False,
        "justified": True,
        "authentication": "NONE_NO_KEY_MANAGEMENT",
        "header_is_authoritative": False,
        "anchor": "EXPORT_MANIFEST",
        "undetectable_without_anchor": UNAUTHENTICATED_HEADER_NOTE,
        "gives": [
            "DETECTION of post-export modification of an exported event stream",
            "detection of header-inconsistent tampering (SEQ_GAP, HEADER_MISMATCH, ...)",
            "an export manifest that re-checks against a re-exported entry list",
            "an authoritative manifest comparison (verify_against_manifest) that catches a "
            "coherent rewrite of the entries and the unauthenticated header",
        ],
        "does_not_give": [
            "it does NOT make the HGK database tamper-proof",
            "it is NOT a cryptographic signature (there is no key management)",
            "the header is NOT authoritative and carries no signature or key management",
            "a coherent rewrite of both the entries and the unauthenticated header is "
            "undetectable without an external anchor (the manifest is the anchor)",
            "it is read-only with respect to HG-KSEOS (it never writes to HGK)",
            "it should NOT be backported into the accepted W1 subject for evidence aesthetics",
        ],
    }
