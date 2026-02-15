"""ScanEngine orchestrator — discover → analyze → report."""

from __future__ import annotations

from typing import TYPE_CHECKING

from llm_authz_audit.analyzers import get_registered_analyzers
from llm_authz_audit.core.config import ToolConfig
from llm_authz_audit.core.context import ScanContext
from llm_authz_audit.core.discovery import FileDiscovery
from llm_authz_audit.core.finding import Confidence, Finding, Severity

if TYPE_CHECKING:
    from llm_authz_audit.analyzers.base import BaseAnalyzer


class ScanEngine:
    """Main orchestrator for the scanning pipeline."""

    def __init__(self, config: ToolConfig) -> None:
        self.config = config
        self._analyzers: list[BaseAnalyzer] | None = None

    @property
    def analyzers(self) -> list[BaseAnalyzer]:
        if self._analyzers is None:
            self._analyzers = self._build_analyzer_list()
        return self._analyzers

    def _build_analyzer_list(self) -> list[BaseAnalyzer]:
        all_classes = get_registered_analyzers()
        instances = [cls() for cls in all_classes]
        if self.config.enabled_analyzers:
            enabled = {a.lower() for a in self.config.enabled_analyzers}
            instances = [a for a in instances if a.name.lower() in enabled]
        return instances

    def scan(self) -> ScanResult:
        # 1. File discovery
        diff_files = None
        if self.config.diff_ref:
            from llm_authz_audit.core.discovery import get_diff_files
            diff_files = get_diff_files(self.config.target_path, self.config.diff_ref)

        discovery = FileDiscovery(
            self.config.target_path,
            exclude_patterns=self.config.exclude_patterns,
            diff_files=diff_files,
        )
        files = discovery.discover()

        # 2. Build scan context
        context = ScanContext(
            target_path=self.config.target_path,
            files=files,
            config=self.config,
        )

        # 3. Run analyzers
        all_findings: list[Finding] = []
        analyzers_run: list[str] = []
        analyzers_skipped: list[str] = []

        for analyzer in self.analyzers:
            if analyzer.should_run(context):
                findings = analyzer.analyze(context)
                all_findings.extend(findings)
                analyzers_run.append(analyzer.name)
            else:
                analyzers_skipped.append(analyzer.name)

        # 4. Cross-file auth context: lower EP001/EP003 confidence if project has auth
        from llm_authz_audit.analyzers.auth_context import build_auth_context
        auth_ctx = build_auth_context(context)
        if auth_ctx.has_project_auth:
            for f in all_findings:
                if f.rule_id in ("EP001", "EP003"):
                    f.confidence = Confidence.LOW
                    f.metadata["auth_context"] = auth_ctx.summary

        # 5. Deduplicate
        all_findings = self._deduplicate(all_findings)

        # 5. Apply suppressions
        if self.config.suppress_file:
            from llm_authz_audit.core.suppression import SuppressionLoader, apply_suppressions
            suppressions = SuppressionLoader.load(self.config.suppress_file)
            all_findings = apply_suppressions(all_findings, suppressions)

        # 6. Filter by minimum confidence
        if self.config.min_confidence is not None:
            all_findings = [f for f in all_findings if f.confidence >= self.config.min_confidence]

        # 7. Sort by severity (critical first)
        all_findings.sort(key=lambda f: f.severity, reverse=True)

        # 8. Determine exit code
        fail_threshold = self.config.fail_on
        has_failures = any(f.severity >= fail_threshold for f in all_findings)

        return ScanResult(
            findings=all_findings,
            files_scanned=len(files),
            analyzers_run=analyzers_run,
            analyzers_skipped=analyzers_skipped,
            exit_code=1 if has_failures else 0,
        )

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, int | None]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = f.unique_key
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


class ScanResult:
    """Container for scan results."""

    def __init__(
        self,
        findings: list[Finding],
        files_scanned: int,
        analyzers_run: list[str],
        analyzers_skipped: list[str],
        exit_code: int,
    ) -> None:
        self.findings = findings
        self.files_scanned = files_scanned
        self.analyzers_run = analyzers_run
        self.analyzers_skipped = analyzers_skipped
        self.exit_code = exit_code

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts
