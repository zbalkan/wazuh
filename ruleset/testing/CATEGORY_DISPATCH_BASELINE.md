# Category-dispatch baseline (Wazuh 4.14.10)

This test suite characterizes the **existing** category-based analysisd rule-selection behavior before the decoder-driven dispatch refactor. It does not propose new production behavior.

## Running

From `ruleset/testing`, with Wazuh installed at `/var/ossec`:

`sudo python3 runtests.py --path /var/ossec --testfile category_dispatch.ini --skip-windows-eventchannel`

The upstream integration workflow runs `runtests.py` against all non-GeoIP `.ini` files by default; pass `--geoip` to include the GeoIP cases. It provisions matching `test_*_decoders.xml` and `test_*_rules.xml` fixture files. These tests require a built and installed Wazuh manager; Python syntax checks alone do not validate the engine.

## Covered behavior

| Case | Legacy expectation | Future treatment |
| --- | --- | --- |
| Recognized syslog decoder | Syslog-category root is eligible | Decoder-specific dispatch |
| Recognized firewall decoder | Firewall-category root is eligible | Decoder-specific dispatch; separate firewall output policy |
| Recognized IDS decoder | IDS-category root is eligible | Decoder-specific dispatch |
| Cross-category decoy | Not eligible, even if `decoded_as` matches | Revisit during ruleset migration |
| `if_sid` descendant | Inherits the parent's IDS category and is reachable through the matching parent root | Preserve rule ancestry |
| Absent `<category>` | Implicit syslog category | Explicit scope; remove default |
| Successful decoder regex | Decoder name and extracted ID are available | Preserve |
| Failed decoder regex after program-name match | Candidate decoder remains assigned | **Known defect:** must change in recognition-contract PR |

The cross-category decoy (rule 999943) intentionally uses `decoded_as=qa_dispatch_ids` with `category=syslog`. Its higher severity and earlier syslog root expose unsafe removal of category gating. A negative `-U` case verifies the decoy does not become the selected rule, while a separate positive case verifies the expected IDS rule.

The dependent-child case (rule 999947) intentionally omits `<category>`: `rules_list.c` copies its parent rule 999942's IDS category when resolving `<if_sid>`. This is distinct from a standalone rule with an implicit SYSLOG default (999948).

The failed-extraction case (rule 999944) deliberately captures existing behavior, not correct behavior. It must be revised with PR-03 when the decoder-match contract changes.

## Important coverage limits

The `-U` assertion in the existing `runtests.py` framework **cannot** positively assert an absent decoder name, even when an INI case contains `decoder =` with an empty value. In `src/analysisd/testrule.c`, the `-U` success path first requires `lf->decoder_info->name != NULL` before comparing the expected decoder and rule. When no decoder matches, the `NULL_Decoder` sentinel has a NULL name, so `-U rule:level:` cannot succeed. Rule 999946 is included for future undecoded-event characterization but is **not considered covered** by this `.ini` suite. An additional runtime test using structured logtest output must confirm its expected matched rule, alert level, absent decoder identity, and original payload.

The `-U` negative convention checks that an exact expected triple is not returned; it does not prove that no unrelated rule fired. Do not use negative cases alone as evidence of detection parity.

These fixtures do not yet cover internal event channels, FIM concurrency, reload, correlation, or archive output. The corresponding roadmap work packages require additional tests.

## Red–Green–Refactor

- **Red:** Use deliberately wrong category routes or invalid decoder-selection outcomes to prove the assertions detect a regression. This mutation testing requires an executable Wazuh installation.
- **Green:** Run the fixtures against the unmodified 4.14.10 baseline.
- **Refactor:** Keep fixture naming and assertions concise; modify production code only in later PRs.

Do not redefine the legacy baseline to make the future dispatch engine pass. Instead, record explicitly approved semantic changes and update the appropriate tests as part of their corresponding PR.
