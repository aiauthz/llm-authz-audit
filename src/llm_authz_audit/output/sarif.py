"""SARIF 2.1.0 output formatter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from llm_authz_audit.output.formatter import BaseFormatter, FormatterFactory

if TYPE_CHECKING:
    from llm_authz_audit.core.engine import ScanResult

_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


class SARIFFormatter(BaseFormatter):
    def format(self, result: ScanResult) -> str:
        # Deduplicate rules from findings
        rules: list[dict] = []
        rule_index: dict[str, int] = {}

        for finding in result.findings:
            if finding.rule_id not in rule_index:
                rule_index[finding.rule_id] = len(rules)
                rule_def: dict = {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.title},
                    "defaultConfiguration": {
                        "level": _SEVERITY_MAP.get(finding.severity.value, "warning"),
                    },
                }
                if finding.remediation:
                    rule_def["help"] = {"text": finding.remediation}
                properties: dict = {}
                if finding.owasp_llm:
                    properties["owasp_llm"] = finding.owasp_llm
                if properties:
                    rule_def["properties"] = properties
                rules.append(rule_def)

        # Build results
        results: list[dict] = []
        for finding in result.findings:
            sarif_result: dict = {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": _SEVERITY_MAP.get(finding.severity.value, "warning"),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            **(
                                {"region": {"startLine": finding.line_number}}
                                if finding.line_number is not None
                                else {}
                            ),
                        }
                    }
                ],
            }
            results.append(sarif_result)

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "llm-authz-audit",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)


FormatterFactory.register("sarif", SARIFFormatter)
