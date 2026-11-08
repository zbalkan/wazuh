# A-01: Wazuh 4.14.12 category-dispatch characterization

**Pinned baseline:** upstream `wazuh/wazuh` branch `4.14.12`, initial SHA `318ecfc1319c33a46a5b50cd9ee7ab200f9e6383`.

This is a **legacy behavior baseline**, not a suggested implementation. The fixtures intentionally use `<category>` and existing roots 1–7. Keep them unchanged when migrating category placement in A-02.

## Run

Build and install the pinned Wazuh 4.14.12 manager, then run from `ruleset/testing`:

`sudo python3 runtests.py --path /var/ossec --testfile a01_category.ini --skip-windows-eventchannel`

The existing `4_testintegration_ruleset.yml` runs the full ruleset integration suite on pull requests. Its AWS compilation cache is upstream-only; forks use a direct build.

## Fixtures

- `ruleset/test_a01_category_decoders.xml`: three fixed `program_name` decoders with syslog, IDS and firewall types.
- `ruleset/test_a01_category_rules.xml`: twelve custom rule definitions; all rule IDs are within the six-digit range.
- `tests/a01_category.ini`: twelve single-event `wazuh-logtest -U` assertions.

The INI runner starts a separate logtest process for every log input. Therefore **no INI assertion here validates multi-event history**, frequency tracking or mutable state across separate events.

| Fixture | Expected behavior | Limitation |
| --- | --- | --- |
| 999950 | Syslog category dispatch reaches matching decoder | Logtest only |
| 999951 | Explicit `if_sid` child preempts matching parent | No path trace beyond final ID |
| 999952 | Missing `<category>` defaults to syslog | Deliberately legacy |
| 999953 | IDS decoder reaches IDS tree | Does not test firewall/IDS special output paths |
| 999954 | Higher-priority cross-category decoy does not intercept an IDS event | Negative `-U` only; positive companion is 999953 |
| 999955 | Child of IDS rule inherits category | Match path inferred from selected child |
| 999956 | Firewall category rule under built-in rule 4100 | Event lacks production firewall fields; **not** a production firewall test |
| 999957–999959 | Noalert parent returns NULL when child fails; returns child when it matches | Does not inspect internal state counters |
| 999960 | Level-zero child prevents the parent from being selected | Negative triple does not prove exact suppression mechanism |
| 999961 | One `if_sid` rule reachable beneath two different parents | Does not compare every physical RuleNode placement |

All expected output is anchored to the original 4.14.12 behavior. If a test differs in CI, characterize the observed result before deciding whether a fixture or implementation change is justified.

## Further A-01 acceptance work

The following are **not yet proved** by the twelve INI assertions:

1. Loaded-tree snapshot with ordered node placements and priority/accuracy encoding.
2. Rule-ID parser/attachment boundaries: ID 0, 1, 999999, 1000000, leading zeros, overflow and malformed `if_sid`/`if_matched_sid`.
3. Positive unmatched-decoder assertion. `wazuh-logtest -U` requires a non-NULL decoder name and cannot assert the `NULL_Decoder` sentinel.
4. Real production-path firewall event with all required fields, internal decoders, and forwarded alerts.
5. Temporal and FTS state, `check_diff`, ignore windows, reload safety and shared-decoder data races.

The race fix belongs in A-03/A-04; this baseline must first record current behavior. A-07 will perform full differential replay against A, including production-specific behavior.

## Red/green approach

First establish green on the unmodified upstream code. Mutate selected expected rule IDs or category assignments to verify the suite fails when reachability changes. Keep those mutations out of commits. Later compare the migration against these original expectations; do not edit the baseline to make it pass.

**Do not merge this PR as a completed A-01 acceptance gate until the remaining required characterization is addressed or explicitly moved into a separately tracked A-01 continuation.**
