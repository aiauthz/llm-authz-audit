"""Machine-readable JSON output for CI/CD."""

from __future__ import annotations

import json

from llm_authz_audit.core.engine import ScanResult
from llm_authz_audit.output.formatter import BaseFormatter, FormatterFactory


class JSONFormatter(BaseFormatter):
    def format(self, result: ScanResult) -> str:
        output = {
            "findings": [f.to_dict() for f in result.findings],
            "summary": {
                "files_scanned": result.files_scanned,
                "analyzers_run": result.analyzers_run,
                "analyzers_skipped": result.analyzers_skipped,
                "total_findings": len(result.findings),
                "by_severity": result.summary,
                "exit_code": result.exit_code,
            },
        }
        return json.dumps(output, indent=2)


FormatterFactory.register("json", JSONFormatter)
