# SWOF W1-STAGE evidence (read-only external acceptance)

Subject: `shw097-team/SWOF`, branch `codex/swof-w1-stage`, `source_candidate_sha = 0ddf00be6bd779b375368d5f4e647d8bccf1b81b`.

**Reduced claim.** W1-STAGE snapshot only. W0 and W1 are implemented and independently verified
locally; W2-W5 are `PLANNED_NOT_DISPATCHED`. This is NOT the order's W0-W5 final candidate, and no
verdict here is acceptance of W0-W5 as a whole.

**Non-claims.** NOT externally accepted (by the executor), NOT released, NOT production, no runtime
claim, no world-effect claim. No PR merge is authorized.

## Ordered read-only verification

1. Check out `0ddf00be6bd779b375368d5f4e647d8bccf1b81b`; confirm `git status --porcelain` is empty.
2. Run each test root separately (`src/` is not an importable package root):
   `tests`=15, `src/fabric/tests`=21, `src/knowledge/tests`=25, `src/admission/tests`=17 -> 78.
3. Falsify `tools/pd04/factory.py`: a packet missing any of the 7 RBWI 10.4 refs must raise FAIL_PD04_ROUTE.
4. Falsify `src/fabric`: bind before VALIDATED; denied permission; missing exit/fallback/rollback;
   provider field in the semantic source -> all must fail.
5. Falsify `src/knowledge`: high-score-but-ineligible candidate cannot ground; GROUNDED != acceptance;
   revoked generation cannot be resurrected; REVOKE-as-STALE must raise ORTHOGONAL_TRUST_FACETS;
   injection must quarantine.
6. Falsify `src/admission`: uninstalled-but-selected, rejected, and provider-off-missing rows must all
   refuse activation; BUILD_NEW_EXCEPTION must be refused unless every earlier disposition fails WITH evidence.
7. Read `DEFECT_LEDGER.json` and judge whether the disclosed defects and residuals are acceptable for the scope.
