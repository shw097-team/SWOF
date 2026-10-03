# Knowledge / Data Brain seam (W1-002)

Source basis: `PI-PKG-05` H1-07 (Data Brain / Retrieval / Knowledge / Source Fabric),
D05-H1-03 (four orthogonal query-time objects + lifecycle invariants),
D05-H1-04 (QueryClass/UseClass routing), and the 18.1 threat table.

## The law this seam enforces

```text
AVAILABLE source   != ELIGIBLE source
ELIGIBLE source    != RETRIEVED candidate
RETRIEVED candidate!= GROUNDED witness
GROUNDED answer    != ACCEPTED package/release
STALE              != REVOKED
DELETED/REVOKED generation MUST NOT be resurrected from index/cache/embedding
```

Retrieval can never launder into authority. `RetrievalPlan` says *how to look*,
`CandidateEnvelope` says *what a lane returned with lineage*, `GroundingResult` says *which
atomic claims are supported by valid witnesses*, `RetrievalEvaluation` says *how the system
performed*. Their states cannot be inferred from each other, and none is an acceptance.

External content is **DATA**: `SourceRecord.authority` is pinned `False` and cannot be set true;
injection triggers `STOP + QUARANTINE + TT` for the affected operation only, while unrelated
compilation continues.
