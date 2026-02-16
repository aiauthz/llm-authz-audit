<p align="center">
  <img src="https://raw.githubusercontent.com/aiauthz/llm-authz-audit/main/docs/logo.svg" alt="llm-authz-audit logo" width="520"/>
</p>


[![npm](https://img.shields.io/np
m/v/llm-authz-audit)](https://www.npmjs.com/package/llm-authz-audit)
[![PyPI](https://img.shields.io/pypi/v/llm-authz-audit)](https://pypi.org/project/llm-authz-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-245%20passing-brightgreen)]()

Scan your LLM-powered applications for authorization gaps, leaked credentials, missing rate limits, prompt injection risks, and other security issues — before they reach production.

```
  ╦   ╦   ╔╦╗
  ║   ║   ║║║
  ╩═╝ ╩═╝ ╩ ╩   authz-audit
```

## Quick Start

```bash
# With npx (no install needed)
npx llm-authz-audit scan .

# Or install via pip
pip install llm-authz-audit
llm-authz-audit scan .
```

## What It Checks

llm-authz-audit ships with **13 analyzers** and **27 rules** covering the OWASP Top 10 for LLM Applications:

| Analyzer | ID Prefix | What It Detects | OWASP |
|---|---|---|---|
| **PromptInjectionAnalyzer** | `PI` | Unsanitized user input in prompts, string concat in prompts, missing delimiters | LLM01 |
| **SecretsAnalyzer** | `SEC` | Hardcoded API keys, tokens, and passwords in Python, JS, and TS files | LLM06 |
| **EndpointAnalyzer** | `EP` | Unauthenticated FastAPI/Flask endpoints serving LLM functionality | LLM06 |
| **JSEndpointAnalyzer** | `EP` | Unauthenticated Express/Node.js endpoints with LLM calls | LLM06 |
| **ToolRBACAnalyzer** | `TR` | LangChain/LlamaIndex tools without RBAC or permission checks | LLM06 |
| **RAGACLAnalyzer** | `RAG` | Vector store retrievals without document-level access controls | LLM06 |
| **MCPPermissionAnalyzer** | `MCP` | Over-permissioned MCP server configurations | LLM06 |
| **SessionIsolationAnalyzer** | `SI` | Shared conversation memory without user/session scoping | LLM06 |
| **RateLimitingAnalyzer** | `RL` | LLM endpoints without rate limiting middleware | LLM04 |
| **OutputFilteringAnalyzer** | `OF` | LLM output used without content filtering or PII redaction | LLM02 |
| **CredentialForwardingAnalyzer** | `CF` | Credentials forwarded to LLM via prompt templates | LLM06 |
| **AuditLoggingAnalyzer** | `AL` | LLM API calls without surrounding audit logging (per-call proximity detection) | LLM09 |
| **InputValidationAnalyzer** | `IV` | User input passed directly to LLM without validation | LLM01 |

## Output Formats

### Console (default) — Semgrep-style

```
╭──────────────────╮
│ 16 Code Findings │
╰──────────────────╯

    api/__init__.py
   ❯❯❱ EP001  [LLM06]
          Unauthenticated LLM endpoint
          29┆ @app.route('/api/v1/predict', methods=['POST'])
          fix: Add authentication dependency: Depends(get_current_user)

    api/model_service.py
   ❯❱ AL001  [LLM09]
          LLM API call without logging
          16┆ r = openai.Moderation.create(
          fix: Add logging around LLM API calls for audit purposes.

╭──────────────╮
│ Scan Summary │
╰──────────────╯
  ⚠ Findings: 16 (2 blocking)
  • Analyzers run: 8
  • Files scanned: 13
  • ❯❯❱ High: 2
  • ❯❱ Medium: 14
```

### JSON

```bash
llm-authz-audit scan . --format json
```

### SARIF (GitHub Code Scanning)

```bash
llm-authz-audit scan . --format sarif > results.sarif
```

Upload to GitHub Code Scanning for inline PR annotations — see [CI/CD Integration](#cicd-integration).

## Installation

### npx (recommended for quick scans)

```bash
npx llm-authz-audit scan .
```

Requires Python >= 3.11 on your PATH. The npm wrapper automatically creates an isolated venv and installs the tool.

### pip / pipx

```bash
# Install globally
pip install llm-authz-audit

# Or use pipx for isolation
pipx install llm-authz-audit
```

### From source

```bash
git clone https://github.com/aiauthz/llm-authz-audit.git
cd llm-authz-audit
pip install -e ".[dev]"
```

## Usage

### `scan` — Analyze a project

```bash
llm-authz-audit scan [PATH] [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--format` | `console` | Output format: `console`, `json`, or `sarif` |
| `--fail-on` | `high` | Minimum severity for non-zero exit: `critical`, `high`, `medium`, `low` |
| `--analyzers` | all | Comma-separated list of analyzers to enable |
| `--exclude` | — | Comma-separated glob patterns to skip |
| `--min-confidence` | — | Minimum confidence to include: `low`, `medium`, `high` |
| `--suppress` | — | Path to suppression YAML file |
| `--extra-rules` | — | Comma-separated paths to custom rule YAML directories |
| `--diff` | — | Only scan files changed since this git ref (e.g. `HEAD~1`, `main`) |
| `--ai` | off | Enable LLM-powered deep analysis |
| `--ai-provider` | `anthropic` | AI provider: `openai` or `anthropic` |
| `--ai-model` | `claude-sonnet-4-5-20250929` | AI model to use |
| `--ai-max-findings` | `20` | Max findings to send to AI (cost guardrail) |
| `--config` | — | Path to `.llm-audit.yaml` config file |
| `-q, --quiet` | off | Suppress the intro banner |
| `-v, --verbose` | off | Show debug output |

Examples:

```bash
# Scan current directory
llm-authz-audit scan .

# Scan with SARIF output, fail only on critical
llm-authz-audit scan ./my-app --format sarif --fail-on critical

# Scan with specific analyzers
llm-authz-audit scan . --analyzers SecretsAnalyzer,EndpointAnalyzer

# Exclude test files
llm-authz-audit scan . --exclude "tests/*,*.test.py"

# Filter out low-confidence noise
llm-authz-audit scan . --min-confidence medium

# Only scan files changed since main
llm-authz-audit scan . --diff main

# Suppress known findings
llm-authz-audit scan . --suppress .llm-audit-suppress.yaml

# Load custom rules
llm-authz-audit scan . --extra-rules ./my-rules,./team-rules
```

### `list-analyzers` — Show available analyzers

```bash
llm-authz-audit list-analyzers
```

### `list-rules` — Show all rules

```bash
llm-authz-audit list-rules

# Include custom rules
llm-authz-audit list-rules --extra-rules ./my-rules
```

### `init` — Generate config template

```bash
llm-authz-audit init
```

Creates a `.llm-audit.yaml` in the current directory with sensible defaults.

## Rules Reference

### Prompt Injection (PI) — LLM01

| Rule | Severity | Description |
|---|---|---|
| `PI001` | CRITICAL | Unsanitized user input in LLM prompt (f-string / `.format()`) |
| `PI002` | HIGH | Direct string concatenation in LLM prompt |
| `PI003` | MEDIUM | Missing prompt/input delimiter between system and user content |

### Secrets (SEC) — LLM06

| Rule | Severity | Description |
|---|---|---|
| `SEC001` | CRITICAL | Hardcoded OpenAI API key |
| `SEC002` | CRITICAL | Hardcoded Anthropic API key |
| `SEC003` | CRITICAL | Hardcoded HuggingFace API token |
| `SEC004` | CRITICAL | Hardcoded AWS access key |
| `SEC005` | HIGH | Hardcoded generic API key or secret |
| `SEC006` | HIGH | Hardcoded password |

Secrets rules scan Python, JavaScript, and TypeScript files.

### Endpoints (EP) — LLM06

| Rule | Severity | Description |
|---|---|---|
| `EP001` | HIGH | Unauthenticated LLM endpoint (FastAPI/Flask) |
| `EP002` | MEDIUM | LLM endpoint without rate limiting |
| `EP003` | MEDIUM | Unauthenticated LLM endpoint (Express/Node.js) |

### Tool RBAC (TR) — LLM06

| Rule | Severity | Description |
|---|---|---|
| `TR001` | HIGH | LangChain tool without permission checks |
| `TR002` | CRITICAL | Destructive LangChain tool without safeguards |
| `TR003` | HIGH | LlamaIndex FunctionTool without permission checks |

### RAG Access Control (RAG) — LLM06

| Rule | Severity | Description |
|---|---|---|
| `RAG001` | HIGH | Vector store retrieval without metadata filtering |
| `RAG002` | HIGH | LlamaIndex query engine without access controls |

### MCP Permissions (MCP) — LLM06

| Rule | Severity | Description |
|---|---|---|
| `MCP001` | CRITICAL | MCP server with root filesystem access |
| `MCP002` | HIGH | MCP server without authentication |
| `MCP003` | HIGH | MCP wildcard tool grants |

### Session Isolation (SI) — LLM06

| Rule | Severity | Description |
|---|---|---|
| `SI001` | HIGH | Shared conversation memory without user scoping |
| `SI002` | HIGH | LlamaIndex chat memory without user scoping |

### Other Rules

| Rule | Severity | OWASP | Description |
|---|---|---|---|
| `CF001` | CRITICAL | LLM06 | Credential in prompt template |
| `AL001` | MEDIUM | LLM09 | LLM API call without logging |
| `IV001` | MEDIUM | LLM01 | User input passed directly to LLM |
| `OF001` | MEDIUM | LLM02 | LLM output without filtering |
| `RL001` | MEDIUM | LLM04 | Missing rate limiting on LLM endpoint |

## Suppression

### Inline Suppression

Suppress individual findings with `# nosec`:

```python
api_key = "sk-proj-abc123..."  # nosec — used for testing only
```

### YAML Suppression File

Create a suppression file for bulk suppressions:

```yaml
# .llm-audit-suppress.yaml
suppressions:
  - rule_id: SEC001
    file_pattern: "tests/*"
    reason: "Test fixtures with fake keys"

  - rule_id: EP001
    reason: "Public API — auth handled by API gateway"

  - file_pattern: "scripts/*"
    reason: "Internal tooling, not deployed"
```

```bash
llm-authz-audit scan . --suppress .llm-audit-suppress.yaml
```

### Smart Suppression

Patterns are automatically recognized as safe:

```python
# Environment variable — not flagged
api_key = os.environ["OPENAI_API_KEY"]

# Auth decorator — EP001 suppressed
@app.post("/chat")
@login_required
def chat_endpoint(request): ...

# Rate limiter present — RL001 suppressed
@limiter.limit("10/minute")
@app.post("/chat")
def chat_endpoint(request): ...
```

### Cross-file Auth Context

When your project uses authentication middleware (FastAPI `Depends()`, Flask `login_required`, Express Passport/JWT), endpoint findings (EP001/EP003) are automatically downgraded to LOW confidence. Use `--min-confidence medium` to filter them out.

## Configuration

Generate a config file with `llm-authz-audit init`, or create `.llm-audit.yaml` manually:

```yaml
# Output format: console, json, or sarif
format: console

# Minimum severity to cause non-zero exit
fail_on: high

# Analyzers to enable (omit to enable all)
# analyzers:
#   - SecretsAnalyzer
#   - EndpointAnalyzer
#   - PromptInjectionAnalyzer

# Glob patterns to exclude
exclude:
  - "tests/*"
  - "*.test.py"

# AI-powered deep analysis
ai:
  enabled: false
  provider: anthropic
  model: claude-sonnet-4-5-20250929
```

## AI Mode

Enable LLM-powered analysis to reduce false positives:

```bash
# Using Anthropic (default)
export ANTHROPIC_API_KEY=your-key
llm-authz-audit scan . --ai

# Using OpenAI
export OPENAI_API_KEY=your-key
llm-authz-audit scan . --ai --ai-provider openai

# Limit AI cost (default: 20 findings max)
llm-authz-audit scan . --ai --ai-max-findings 10
```

AI mode sends each finding's surrounding code context to the LLM for review. Findings classified as false positives are automatically dropped. The `--ai-max-findings` flag caps the number of findings sent to the LLM (sorted by severity, highest first) to control costs.

Requires the `ai` extra:

```bash
pip install llm-authz-audit[ai]
```

## CI/CD Integration

### GitHub Actions — Basic

```yaml
name: LLM Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install llm-authz-audit
      - run: llm-authz-audit scan . --format json --fail-on high
```

### GitHub Actions — SARIF (Code Scanning)

Upload SARIF results to get inline annotations on pull requests:

```yaml
name: LLM Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install llm-authz-audit
      - run: llm-authz-audit scan . --format sarif > results.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitHub Actions — Diff Mode (PR only)

Scan only files changed in the PR:

```yaml
- run: llm-authz-audit scan . --diff origin/main --format sarif > results.sarif
  continue-on-error: true
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings above threshold |
| `1` | Findings above `--fail-on` severity detected |
| `2` | Invalid arguments or runtime error |

## Custom Rules

Add your own rules as YAML files:

```yaml
# my-rules/custom.yaml
rules:
  - id: CUSTOM001
    title: "Internal API called without auth header"
    severity: high
    owasp_llm: LLM06
    file_types: ["*.py"]
    pattern: "requests\\.(?:get|post)\\(.+internal-api"
    negative_pattern: "headers.*[Aa]uth"
    remediation: "Add Authorization header to internal API calls."
```

```bash
llm-authz-audit scan . --extra-rules ./my-rules
llm-authz-audit list-rules --extra-rules ./my-rules
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, how to add analyzers and rules, and PR guidelines.

## License

[MIT](LICENSE)
