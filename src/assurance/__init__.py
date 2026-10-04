"""SWOF assurance / evidence / segregation-of-duties substrate (W2, WO-SWOF-W2-003).

This package is the substrate that DECIDES pass/fail, so its central design law is that a
checker that cannot fail is the defect. Every rejection class is a typed error with its own
`reason_code`, every rejection class is injected by an adversarial test, and no assertion is
ever initialised and left unreachable.

- `predicate.py` - falsifiable acceptance predicates (a predicate with no negative fixtures is
  refused: it cannot fail, so it is not a predicate).
- `oracle.py` - first-failure verdicts over evidence items; an undefined oracle is ambiguous,
  and an unrepresented negative fixture never passes.
- `evidence.py` - raw-proof / subject / environment / linkage binding, with separate
  linkage-mode counters so one mixed counter cannot over- and under-report at once.
- `sod.py` - maker != checker, and a checker that can never write the product.
- `journal.py` - a DETECTION-ONLY digest-chain envelope over an EXPORTED lifecycle stream. It
  is not a signature and is read-only with respect to HG-KSEOS.

Non-claims: this package owns no Product Truth and no Semantic Truth, green execution does not
inherit acceptance, and nothing here is released or production.
"""

__all__ = ["predicate", "oracle", "evidence", "sod", "journal"]