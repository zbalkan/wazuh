#!/usr/bin/env python3
from health_test.test_suite import UnitResultInterface, UnitOutput, run as suite_run
import re
from pathlib import Path
import shared.resource_handler as rs
import sys


class UnitResult(UnitResultInterface):
    def __init__(self, index: int, expected: dict, actual: UnitOutput, target: str, help: str):
        self.index = index
        self.expected = expected
        self.success = actual.success
        self.target = target
        self.diff = {}
        self.load_allowed_rule_mapping(Path(help) / 'ruleset' / 'base-rules' / 'allowed_rule_mapping.yml')

        if not self.success:
            self.error = actual.error
            return

        self.setup(actual.output)

    def setup(self, actual_output: dict):
        traces = actual_output.get('traces', [])
        any_asset = False
        for trace in traces:
            if self.is_decoder_asset(trace.get('asset')) and trace.get('success'):
                any_asset = True
                self.check_trace(trace)

        if not any_asset:
            self.diff.setdefault(self.index, {}).setdefault("events_not_consumed", {}).update({
                "status": "events not consumed by any decoder",
                "event": actual_output['output']['event']['original']
            })
            self.success = False

    def is_decoder_asset(self, asset: str) -> bool:
        parts = asset.split('/')
        return len(parts) == 3 and parts[0] == 'decoder'

    def check_trace(self, trace: dict):
        invalid_fields = []
        for trace_detail in trace.get('traces', []):
            field, operation = trace_detail.split(':', 1)
            field = field.strip()
            operation = operation.strip()
            if self.is_valid_operation(operation):
                base_field = re.sub(r'\.\d+$', '', field)
                if not self.is_valid_field(base_field):
                    invalid_fields.append(base_field)

        if invalid_fields:
            self.diff.setdefault(self.index, {}).setdefault("decoder_fields", {}).update({
                "status": "Invalid fields detected",
                "invalid_mapped_fields": invalid_fields
            })
            self.success = False

    def is_valid_field(self, field: str) -> bool:
        return not (field in self.allowed_rule_mapping or field.startswith("rule"))

    def is_valid_operation(self, operation: str) -> bool:
        valid_patterns = [
            r'^map\([^\)]*\)\s*->\s*.*$',
            r'^array_append\([^\)]*\)\s*->\s*.*$'
        ]
        return any(re.match(pattern, operation) for pattern in valid_patterns)

    def load_allowed_rule_mapping(self, allowed_rule_mapping_path: Path):
        try:
            self.allowed_rule_mapping = rs.ResourceHandler().load_file(allowed_rule_mapping_path.as_posix())
        except Exception as e:
            return f"Error loading allowed rule mapping from '{allowed_rule_mapping_path}': {e}"


def run(args):
    if not args["integration"]:
        args["target"] = "decoder"
    return suite_run(args, UnitResult, debug_mode="-dd")
