"""AI-powered deep analysis — runs after static analysis to refine findings."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from llm_authz_audit.core.finding import Confidence, Finding, Severity
from llm_authz_audit.llm.prompts import SYSTEM_PROMPT, build_finding_review_prompt
from llm_authz_audit.llm.providers import get_provider

if TYPE_CHECKING:
    from llm_authz_audit.core.engine import ScanEngine, ScanResult
    from llm_authz_audit.llm.providers import LLMProvider


class AIAnalyzer:
    """Refines static analysis findings using LLM reasoning."""

    def __init__(
        self,
        provider: str = "anthropic",
        model: str = "claude-sonnet-4-5-20250929",
        llm_client: LLMProvider | None = None,
    ) -> None:
        self._provider = llm_client or get_provider(provider, model)

    def refine(self, result: ScanResult, engine: ScanEngine) -> ScanResult:
        """Review each finding with the LLM and update confidence."""
        refined_findings: list[Finding] = []

        for finding in result.findings:
            context = self._get_context(finding, engine)
            prompt = build_finding_review_prompt(
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity.value,
                file_path=finding.file_path,
                line_number=finding.line_number,
                snippet=finding.snippet,
                description=finding.description,
                context=context,
            )

            try:
                response = self._provider.complete(prompt, system=SYSTEM_PROMPT)
                verdict, confidence, explanation = self._parse_response(response)

                if verdict == "FALSE_POSITIVE":
                    continue  # Drop false positives

                finding.confidence = Confidence.AI_VERIFIED
                finding.metadata["ai_explanation"] = explanation
                finding.metadata["ai_confidence"] = confidence
            except Exception:
                # If AI fails, keep original finding
                pass

            refined_findings.append(finding)

        result.findings = refined_findings
        return result

    def _get_context(self, finding: Finding, engine: ScanEngine) -> str:
        """Get surrounding code context for a finding."""
        from pathlib import Path

        file_path = engine.config.target_path / finding.file_path
        if not file_path.exists():
            return finding.snippet

        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            return finding.snippet

        if finding.line_number is None:
            return "\n".join(lines[:50])

        start = max(0, finding.line_number - 10)
        end = min(len(lines), finding.line_number + 10)
        context_lines = []
        for i in range(start, end):
            marker = ">>>" if i + 1 == finding.line_number else "   "
            context_lines.append(f"{marker} {i + 1:4d} | {lines[i]}")
        return "\n".join(context_lines)

    def _parse_response(self, response: str) -> tuple[str, str, str]:
        """Parse LLM response into verdict, confidence, and explanation."""
        verdict = "TRUE_POSITIVE"
        confidence = "MEDIUM"
        explanation = response

        verdict_match = re.search(r"VERDICT:\s*(TRUE_POSITIVE|FALSE_POSITIVE)", response)
        if verdict_match:
            verdict = verdict_match.group(1)

        confidence_match = re.search(r"CONFIDENCE:\s*(HIGH|MEDIUM|LOW)", response)
        if confidence_match:
            confidence = confidence_match.group(1)

        explanation_match = re.search(r"EXPLANATION:\s*(.+?)(?:REMEDIATION:|$)", response, re.DOTALL)
        if explanation_match:
            explanation = explanation_match.group(1).strip()

        return verdict, confidence, explanation
