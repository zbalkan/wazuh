# Category-free rule graph roadmap (Wazuh 4.14.12)

## Baseline and intent

- **Upstream source:** `wazuh/wazuh`, branch `4.14.12`.
- **Pinned initial commit:** `318ecfc1319c33a46a5b50cd9ee7ab200f9e6383` (2026-11-06).
- **Clean integration branch:** `refactor/decoder-driven-dispatch-v4.14.12`.
- **First task branch:** `test/a01-category-dispatch-baseline-v4.14.12`.
- **Previous experiments:** 4.14.10 branches and PRs are not parents of this work and must not be cherry-picked.
- **Goal:** Remove rule-category dispatch, eventually using effective decoder identity and a virtual structural root; preserve established DFS/first-returned-match semantics.

This is a design and work breakdown, not a claim of completed implementation or runtime parity. The source pin is essential: changes in upstream `4.14.12` after the pin require an explicit rebase and revalidation.

## State transitions

| State | Structural placement | Rule eligibility | Historical correlation |
| --- | --- | --- | --- |
| 4.14.12 baseline | Explicit `if_sid`/`if_group`/`if_level` or category fallback | Top-level `RuleInfo.category == decoder_info->type` | `Search_LastEvents` compares decoder types |
| A (compatibility stage) | Explicit parent relationships under existing root rules 1–7 | Early exact event-owned type predicate on each existing root | Preserve decoder-type equivalence, evaluated per event |
| B (target) | Explicit structural relationships; otherwise attach to virtual root 0 | Compiled applicability indexed by **effective decoder identity** | Explicit identity scopes; migrate existing cross-decoder correlations |

A is an intermediate compatibility refactor. Do not describe it as decoder-identity dispatch: its seven root partitions remain. B removes those partitions only after each legacy rule has explicit, equivalent applicability.

## Source checkpoints verified against pinned 4.14.12

| Concern | Source path | Baseline mechanism |
| --- | --- | --- |
| Rule ID parsing | `src/analysisd/rules.c`, `getattributes` | Numeric string limited to six characters; does not explicitly reject ID zero |
| Root identification | `src/analysisd/rules.c`, `Rules_OP_ReadRules` | `sigid < 10` creates top-level rule nodes |
| Structural placement | `src/analysisd/rules_list.c`, `OS_AddChild`/`_AddtoRule` | Structural selectors precede category fallback; `sid == 0` is not a normal lookup |
| Match traversal | `src/analysisd/rules.c`, `OS_CheckIfRuleMatch` | Depth-first ordered children, first non-NULL result; `NO_ALERT` returns NULL after children |
| Runtime category gate | `src/analysisd/analysisd.c`, `src/analysisd/logtest.c`, `src/analysisd/testrule.c` | Root-category-versus-decoder-type comparison |
| Historical-event gate | `src/analysisd/eventinfo.c`, `Search_LastEvents` | Decoder-type equality |
| Shared mutable type | `src/analysisd/decoders/plugins/sonicwall_decoder.c` and `ossecalert_decoder.c` | Per-event plugins write through shared `decoder_info->type` |
| Configuration output | `src/analysisd/config_json.c` | Serializes `RuleInfo.category` |

Source findings do not substitute for runtime tests. The 4.14.12 branch includes other changes since 4.14.10, so all fixtures must be regenerated against 4.14.12.

## Milestone A: remove `RuleInfo.category` with parity

| ID | Independently reviewable work | Exit condition |
| --- | --- | --- |
| A-01 | Record 4.14.12 behavior in runtime tests and source/loaded-tree snapshots. Cover root category gating, priority, default category, noalert, level zero, `prev_rule`, implicit placement, duplicate placement, overwrite, custom rules, plugin classification, internal decoders, temporal state, malformed IDs and references. | Captured original behavior; tests fail if matched-path, alerts, state or rule-tree structure change. |
| A-02 | Transpile only **resolved category-fallback placements** into explicit `if_sid`; preserve loader-synthesized relationships for `if_matched_sid`/`if_matched_group`, overwrites and load order. | Identical effective graph and match outcomes under original 4.14.12. |
| A-03 | Add event-owned type and initialize from selected decoder; preserve it in copies and historical storage. | Same behavior for single-threaded events, including unmatched/internal decoders. |
| A-04 | Stop SonicWall and OSSEC-alert plugins writing shared decoder definitions; migrate all type consumers; test concurrent interleavings. | Per-event classification stable; no event-time writes to shared decoder type. |
| A-05 | Compile exact typed `event_type` predicates for roots 1–7; evaluate before other predicates or state effects. | Same eligible roots for each event. |
| A-06 | Remove rule category parser/default/inheritance/overwrite/fallback/serialization and top-level category comparisons in production and test paths. | No remaining `RuleInfo.category` dependency. |
| A-07 | Differential production/logtest/event-sequence tests, correlation, FTS, check_diff, suppression, active response, reload. | All unapproved semantic changes blocked; planned race fix explicitly documented. |

Keep roots 1–7 during A; do not implement virtual root zero or change matching order here.

## Milestone B: decoder-driven rule graph

| ID | Independently reviewable work | Exit condition |
| --- | --- | --- |
| B-01 | Define immutable **effective decoder identity**, including plugin outcome variants, `use_own_name`, internal and unmatched events. Numeric decoder IDs are generation-local. | Deterministic identity for every event, including SonicWall variants. |
| B-02 | Specify IDs, structural-selector precedence, implicit root attachment, explicit decoder applicability and root-zero syntax. | No ambiguity between root placement and temporal selectors. |
| B-03 | Strictly parse IDs and references, resolve all parents and decoder eligibility, reject unresolved/cyclic/oversized graphs, retain duplicated placements. | Validated immutable graph; no partial publication. |
| B-04 | Treat 0 as a **virtual root container**, never a real `RuleInfo`; attach rules with no effective parent beneath it. | Root 0 cannot match, alert, count, hash, correlate or become `prev_rule`. |
| B-05 | Compile effective decoder identity -> ordered eligible entry points; remove A's seven event-type root gates while retaining existing DFS/evaluation order. | Rule selection and state outcomes equivalent to A after eligibility migration. |
| B-06 | Replace type equality in `Search_LastEvents` with explicit `same_decoder`, `decoder_set`, `any_decoder` policies. | Existing cross-decoder matches preserved by migration, not silently narrowed. |
| B-07 | Separate firewall/IDS FTS/generated-alert behavior from rule eligibility; retain functionality via explicit event capabilities/modes. | No category or type partition in rule selection. |
| B-08 | Differential replay versus A, concurrency/TSAN where practical, hot reload and graph-generation safety, ID tests, runtime and memory benchmarks. | Semantic parity and absence of residual category gating. |

## Identifier contract for B (proposed; not yet implemented)

- Real rule IDs are decimal integers **1–999999**. Reject `id=0`, negatives, overflow and non-decimal strings; canonicalize leading zeros for duplicate checks.
- Internal virtual root ID **0** never has a real `RuleInfo`.
- Ordinary `if_sid` references and `if_matched_sid` references target real IDs 1–999999.
- Omitted structural parent defaults to virtual root 0 **after** loader-implied relationships from `if_matched_sid` or `if_matched_group` are resolved.
- An optional explicit `if_sid=0` indicates root placement only in B. Reject a mixed list such as `if_sid=0,5700` initially.
- `if_matched_regex` is a temporal predicate, not by itself a structural parent reference.
- Rules with no `decoded_as` do **not** automatically become globally eligible during migration. Applicability must be explicit or compiled from a separately declared mapping.

The existing 4.14.12 parser's accepted inputs and malformed-input behavior should be recorded in A-01 before validation is tightened in B.

## Required invariant tests

1. Ordered sibling visit sequence (including encoded priority, ties and `accuracy=0`).
2. First returned descendant and `noalert` NULL propagation.
3. Level-0 suppression, `prev_rule`, ignored-alert fallback and post-match effects.
4. Duplicated `if_sid` placements and repeated `if_group`/`if_level` graph expansion.
5. Stateful effects in rejected rules: FTS, diff, historical correlation and counters.
6. Original vs migrated stock ruleset graph snapshots; custom-rule/overwrite cases.
7. Production vs logtest differences; valid firewall event versus incomplete firewall event.
8. Plugin class variants under concurrent decode/process; internal and unmatched decoders.
9. Multi-event correlation replay, event copy, ruleset reload and graph-generation consistency.
10. `id` and `if_sid` boundaries: 0, 1, 999999, 1000000, leading zeros, invalid and overflowing text.

## PR and CI policy

- One branch and focused PR per subtask, with reproduction, expected behavior and negative tests.
- A-01 is a new baseline against **4.14.12**; do not reuse the 4.14.10 expected outputs by assumption.
- Red-green-refactor for any behavior-changing fix.
- Avoid unrelated CI, decoder-recognition, compiler, package or performance modifications.
- Keep category-free dispatch and field/sibling indexing independent. Evaluate optimizations after B-08.
- A only merges after A-07 parity; B only completes after B-08 parity.
