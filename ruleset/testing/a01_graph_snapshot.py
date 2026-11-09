#!/usr/bin/env python3
"""Capture exact selected RuleNode placements from Wazuh 4.14.12's test loader.

Requires the test-only WAZUH_A01_GRAPH_SNAPSHOT hook in analysisd/testrule.c.
Runs against a disposable manager installation; never changes production files.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

EDGE = re.compile(
    r"^A01_RULE_EDGE\t(?P<parent>-?\d+)\t(?P<sibling>\d+)\t"
    r"(?P<rule>-?\d+)\t(?P<level>-?\d+)\t(?P<category>-?\d+)\t"
    r"(?P<depth>\d+)$"
)

# The expected direct parent is a structural property, not inferred from alerts.
EXPECTED_EDGES = {
    (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (0, 7),
    (1, 999950), (1, 999952), (1, 999954), (1, 999957), (1, 999959),
    (3, 999953),
    (999950, 999951), (999950, 999960), (999950, 999961),
    (999953, 999955), (999953, 999961),
    (4100, 999956), (999957, 999958),
}


def capture(home, source, timeout):
    files = (
        (source / "test_a01_category_rules.xml", home / "etc" / "rules" / "test_a01_category_rules.xml"),
        (source / "test_a01_category_decoders.xml", home / "etc" / "decoders" / "test_a01_category_decoders.xml"),
    )
    binary = home / "bin" / "wazuh-logtest"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"missing legacy logtest binary: {binary}")
    for src, dst in files:
        if not src.is_file() or dst.exists():
            raise RuntimeError(f"source missing or installed fixture already exists: {src} -> {dst}")

    copied = []
    try:
        for src, dst in files:
            shutil.copyfile(src, dst)
            dst.chmod(0o644)
            copied.append(dst)

        env = os.environ.copy()
        env["WAZUH_A01_GRAPH_SNAPSHOT"] = "1"
        proc = subprocess.run(
            [str(binary), "-t"],
            cwd=home,
            env=env,
            stdin=subprocess.DEVNULL,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"logtest -t exited {proc.returncode}:\n{proc.stdout[-5000:]}"
            )
        edges = []
        for line in proc.stdout.splitlines():
            match = EDGE.fullmatch(line.strip())
            if match:
                edges.append({key: int(value) for key, value in match.groupdict().items()})
        if not edges:
            raise RuntimeError("no A01_RULE_EDGE lines: test-only binary or graph hook missing")
        return edges
    finally:
        for path in reversed(copied):
            path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path("/var/ossec"))
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent / "ruleset")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    edges = capture(args.home.resolve(), args.source.resolve(), args.timeout)
    actual_pairs = [(edge["parent"], edge["rule"]) for edge in edges]
    actual = set(actual_pairs)
    missing = sorted(EXPECTED_EDGES - actual)
    unexpected = sorted(actual - EXPECTED_EDGES)
    duplicates = sorted({pair for pair in actual if actual_pairs.count(pair) > 1})

    report = {
        "purpose": "A-01 observed loaded-rule-node structural placement",
        "upstream": "wazuh/wazuh 4.14.12",
        "baseline_sha": "318ecfc1319c33a46a5b50cd9ee7ab200f9e6383",
        "edges": edges,
        "missing_edges": missing,
        "unexpected_edges": unexpected,
        "duplicate_edges": duplicates,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Captured {len(edges)} selected RuleNode placements in {args.report}")
    if missing or unexpected or duplicates:
        print(f"Graph differs: missing={missing}, unexpected={unexpected}, duplicates={duplicates}",
              file=sys.stderr)
        return 1
    print("All expected physical RuleNode parent-child placements verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
