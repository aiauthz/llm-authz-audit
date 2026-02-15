"""Prompt templates for AI-powered auth flow analysis."""

from __future__ import annotations

SYSTEM_PROMPT = """You are an expert application security engineer specializing in LLM application security.
You are analyzing code for authentication and authorization vulnerabilities.
Focus on the OWASP Top 10 for LLM Applications.
Be precise and avoid false positives. Only flag real security issues."""

FINDING_REVIEW_PROMPT = """Review the following static analysis finding and determine if it is a true positive or false positive.

## Finding
- Rule ID: {rule_id}
- Title: {title}
- Severity: {severity}
- File: {file_path}:{line_number}
- Snippet: {snippet}
- Description: {description}

## Surrounding Code Context
```python
{context}
```

## Instructions
1. Analyze whether this is a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (not a real issue)
2. If true positive, explain the attack vector and impact
3. If false positive, explain why the detection is incorrect
4. Rate your confidence: HIGH, MEDIUM, or LOW

Respond in this exact format:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: HIGH or MEDIUM or LOW
EXPLANATION: <your analysis>
REMEDIATION: <specific fix if true positive, or "N/A" if false positive>
"""

AUTH_FLOW_ANALYSIS_PROMPT = """Analyze the authentication and authorization flow in this LLM application.

## Files Under Analysis
{files_content}

## Static Analysis Findings
{findings_summary}

## Instructions
Analyze the code for:
1. Authentication bypass paths — can unauthenticated users reach LLM endpoints?
2. Authorization gaps — can users access data/tools beyond their permissions?
3. Multi-file auth flow issues — are auth checks consistent across the codebase?
4. Indirect access paths — can auth be bypassed through helper functions or internal APIs?

For each issue found, respond in this format:
ISSUE: <title>
SEVERITY: CRITICAL or HIGH or MEDIUM or LOW
FILE: <file_path>
LINE: <line_number or "N/A">
DESCRIPTION: <detailed explanation>
REMEDIATION: <specific fix>
---
If no additional issues are found, respond with: NO_ADDITIONAL_ISSUES
"""


def build_finding_review_prompt(
    rule_id: str,
    title: str,
    severity: str,
    file_path: str,
    line_number: int | None,
    snippet: str,
    description: str,
    context: str,
) -> str:
    return FINDING_REVIEW_PROMPT.format(
        rule_id=rule_id,
        title=title,
        severity=severity,
        file_path=file_path,
        line_number=line_number or "N/A",
        snippet=snippet,
        description=description,
        context=context,
    )


def build_auth_flow_prompt(files_content: str, findings_summary: str) -> str:
    return AUTH_FLOW_ANALYSIS_PROMPT.format(
        files_content=files_content,
        findings_summary=findings_summary,
    )
