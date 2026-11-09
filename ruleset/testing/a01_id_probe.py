#!/usr/bin/env python3
"""Record Wazuh 4.14.12 rule-ID/reference boundary behavior using the real loader.

This is a characterization probe, not an enforcement of Milestone B's proposed
ID validation contract. Run only on a disposable Wazuh manager installation.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from xml.sax.saxutils import escape

PROBE_FILENAME = "a01_id_probe_rules.xml"
INTERESTING = re.compile(
    r"rule|signature|if_sid|if_matched|invalid|error|warning|duplicate|overwrite|config",
    re.IGNORECASE,
)

# No fixture is added to the committed ruleset. Cases run one at a time.
CASES = [
    ("id_zero", "id", "0"),
    ("id_zero_padded", "id", "000000"),
    ("id_one_duplicate", "id", "1"),
    ("id_one_padded_duplicate", "id", "000001"),
    ("id_maximum", "id", "999999"),
    ("id_over_maximum", "id", "1000000"),
    ("id_negative", "id", "-1"),
    ("id_nonnumeric", "id", "abc"),
    ("if_sid_zero", "if_sid", "0"),
    ("if_sid_root_one", "if_sid", "1"),
    ("if_sid_mixed_zero", "if_sid", "0,5700"),
    ("if_sid_missing", "if_sid", "9999999"),
    ("if_sid_nonnumeric", "if_sid", "xyz"),
    ("if_matched_sid_zero", "if_matched_sid", "0"),
    ("if_matched_sid_missing", "if_matched_sid", "9999999"),
    ("if_matched_sid_nonnumeric", "if_matched_sid", "xyz"),
]


def make_rule(name, kind, value):
    if kind == "id":
        rule_id, selector = value, ""
    else:
        rule_id = "999970"
        selector = f"<{kind}>{escape(value)}</{kind}>"
    # Distinct rule id 999970 in every *separate* loader invocation.
    return (
        '<group name="qa,a01_id_probe,">\n'
        f'  <rule id="{escape(rule_id)}" level="5">\n'
        "    <category>syslog</category>\n"
        f"    {selector}\n"
        f"    <match>^A01_ID_PROBE_{name}$</match>\n"
        f"    <description>A-01 numeric boundary {name}.</description>\n"
        "  </rule>\n"
        "</group>\n"
    )


def extract_diagnostics(output):
    lines = [line.strip() for line in output.splitlines() if INTERESTING.search(line)]
    # This is a searchable summary, not the full loader output. Preserve
    # stdout separately for interpreting acceptance versus skipped rules.
    return lines[-35:]


def probe(home, target, binary, name, kind, value, timeout):
    try:
        target.write_text(make_rule(name, kind, value), encoding="utf-8")
        target.chmod(0o644)
        run = subprocess.run(
            [str(binary), "-t"],
            cwd=home,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return {
            "name": name,
            "selector": kind,
            "value": value,
            "exit_code": run.returncode,
            "loader_outcome": "completed" if run.returncode == 0 else "failed",
            "diagnostics": extract_diagnostics(run.stdout),
            "stdout": run.stdout,
        }
    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "selector": kind,
            "value": value,
            "loader_outcome": "timeout",
            "timeout_seconds": timeout,
            "diagnostics": [],
        }
    finally:
        target.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path("/var/ossec"))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    home = args.home.resolve()
    binary = home / "bin" / "wazuh-analysisd"
    rule_dir = home / "etc" / "rules"
    target = rule_dir / PROBE_FILENAME

    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"installed analysisd binary not found: {binary}")
    if not rule_dir.is_dir() or target.exists():
        parser.error(f"probe directory missing or reserved file already exists: {target}")
    if not os.access(rule_dir, os.W_OK):
        parser.error(f"write permission required for disposable rules directory: {rule_dir}")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    started = time.time()
    records = []
    try:
        for name, kind, value in CASES:
            result = probe(home, target, binary, name, kind, value, args.timeout)
            records.append(result)
            print(f"{name}: {result['loader_outcome']} (exit {result.get('exit_code', '-')})", flush=True)
    finally:
        # Extra safeguard if the process was interrupted between writes.
        target.unlink(missing_ok=True)

    report = {
        "purpose": "A-01 original loader characterization, not Milestone B acceptance",
        "upstream": "wazuh/wazuh 4.14.12",
        "baseline_sha": "318ecfc1319c33a46a5b50cd9ee7ab200f9e6383",
        "duration_seconds": round(time.time() - started, 2),
        "cases": records,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(records)} cases in {args.report}", flush=True)

    # Fail only if the harness itself did not complete its observations.
    # Do not assert new ID semantics against the legacy implementation.
    return 1 if any(x["loader_outcome"] == "timeout" for x in records) else 0


if __name__ == "__main__":
    sys.exit(main())
