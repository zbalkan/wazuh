# A-01: Wazuh 4.14.12 category-dispatch characterization

**Pinned baseline:** upstream `wazuh/wazuh` branch `4.14.12`, initial SHA `318ecfc1319c33a46a5b50cd9ee7ab200f9e6383`.

This is a **legacy behavior baseline**, not a suggested implementation. The fixtures intentionally use `<category>` and existing roots 1–7. Keep them unchanged when migrating category placement in A-02.

## Run

Build and install the pinned Wazuh 4.14.12 manager, then run from `ruleset/testing`:

`sudo python3 runtests.py --path /var/ossec --testfile a01_category.ini --skip-windows-eventchannel`

The existing `4_testintegration_ruleset.yml` runs the default non-GeoIP ruleset integration tests on pull requests. GeoIP cases require `--geoip` and appropriate GeoIP support. Its AWS compilation cache is upstream-only; forks use a direct build.

## Fixtures

- `ruleset/test_a01_category_decoders.xml`: three fixed `program_name` decoders with syslog, IDS and firewall types.
- `ruleset/test_a01_category_rules.xml`: twelve custom rule definitions; all rule IDs are within the six-digit range.
- `tests/a01_category.ini`: thirteen single-event `wazuh-logtest -U` assertions.

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
| 999957–999959 | `A01_FALLBACK` selects sibling rule 999959; `A01_FALLBACK_CHILD` selects child rule 999958 | The noalert parent returning NULL when no child matches is inferred from these outcomes and the matcher implementation; the tests do not directly inspect return values or counters |
| 999960 | Positive level-zero selection and negative parent-selection assertions | These establish matching precedence, not independently the absence of generated alerts |
| 999961 | One `if_sid` rule reachable beneath two different parents | Does not compare every physical RuleNode placement |

All expected output is anchored to the original 4.14.12 behavior. If a test differs in CI, characterize the observed result before deciding whether a fixture or implementation change is justified.

## Loader-level evidence (additional A-01 probes)

The CI ruleset job now runs two independent scripts **after** the existing INI suite. Both require a disposable, installed manager; they must not be used on an operational Wazuh installation.

- `a01_id_probe.py` creates one temporary XML rule file per case, runs `wazuh-analysisd -t` against the **real loader**, and deletes the rule file in a `finally` block. It records 16 cases covering zero, padded zero, duplicate one, padded one, six-digit maximum, out-of-range and malformed IDs, plus zero, mixed, missing and malformed structural/temporal references. These are **observations of legacy acceptance and warnings**, not assertions that the eventual B validation contract is already implemented. Each case retains full loader stdout and a short diagnostic summary. A successful loader exit does not establish that the particular rule was accepted. Loader exit status alone does not establish whether a rule was inserted.
- `a01_graph_snapshot.py` installs the existing three-decoder and twelve-rule fixtures temporarily, then runs `wazuh-logtest-legacy -t` with `WAZUH_A01_GRAPH_SNAPSHOT=1`. A test-only hook in `src/analysisd/testrule.c`, enabled under `TESTRULE`, emits each selected physical `RuleNode` edge with parent, actual sibling index, ID, level, category and depth. The script checks 20 expected root and parent-child placements, including both insertions of rule 999961. This reads the **loaded graph** rather than reconstructing it from XML.

The hook is inactive without that environment variable and is not present in the production `wazuh-analysisd` executable. It does not change the matcher or loader. The two probes execute independently after a successful manager installation, even when another test or probe fails. The workflow uploads their machine-readable reports as the `a01-baseline-evidence` artifact.

The first CI attempt failed because the snapshot driver invoked the modern Python `wazuh-logtest` entrypoint with unsupported `-t`; the test hook exists in `wazuh-logtest-legacy`. The driver has been corrected. The earlier 15-case ID probe completed and uploaded its report; the new 16-case run and graph snapshot still require CI validation.

The graph assertion covers the focused A-01 fixtures, **not a full stock-rule graph digest**. Once CI confirms the baseline, preserve recorded sibling ordinals and priority data for A-02 graph-equivalence comparisons.

## Further A-01 acceptance work

The following are **not yet proved** by the thirteen INI assertions:

1. Full stock-ruleset loaded-tree snapshot or digest, including ordered placement and priority/accuracy encoding beyond the focused A-01 fixture edges.
2. Runtime-rule membership assertions and fixed expected diagnostics for the boundary cases. The initial probe records loader outcomes but does not yet prove insertion or normalize all warnings; explicit signed-integer overflow characterization remains.
3. Positive unmatched-decoder assertion. `wazuh-logtest -U` requires a non-NULL decoder name and cannot assert the `NULL_Decoder` sentinel.
4. Real production-path firewall event with all required fields, internal decoders, and forwarded alerts.
5. Temporal and FTS state, `check_diff`, ignore windows, reload safety and shared-decoder data races.

The race fix belongs in A-03/A-04; this baseline must first record current behavior. A-07 will perform full differential replay against A, including production-specific behavior.

## Red/green approach

First establish green on the unmodified upstream code. Mutate selected expected rule IDs or category assignments to verify the suite fails when reachability changes. Keep those mutations out of commits. Later compare the migration against these original expectations; do not edit the baseline to make it pass.

**Do not merge this PR as a completed A-01 acceptance gate until the remaining required characterization is addressed or explicitly moved into a separately tracked A-01 continuation.**
