# llm-authz-audit

**Static security analyzer for LLM applications — eslint for LLM security.**

[![npm](https://img.shields.io/npm/v/llm-authz-audit)](https://www.npmjs.com/package/llm-authz-audit)
[![PyPI](https://img.shields.io/pypi/v/llm-authz-audit)](https://pypi.org/project/llm-authz-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-140%20passing-brightgreen)]()

Scan your LLM-powered applications for authorization gaps, leaked credentials, missing rate limits, and other security issues — before they reach production.

## Quick Start

```bash
# With npx (no install needed)
npx llm-authz-audit scan .

# Or install via pip
pip install llm-authz-audit
llm-authz-audit scan .
```

## What It Checks

llm-authz-audit ships with **11 analyzers** covering the most common LLM security pitfalls:

| Analyzer | ID Prefix | What It Detects |
|---|---|---|
| **SecretsAnalyzer** | `SEC` | Hardcoded API keys, tokens, and passwords |
| **EndpointAnalyzer** | `EP` | Unauthenticated FastAPI/Flask endpoints serving LLM functionality |
| **ToolRBACAnalyzer** | `TR` | LangChain/LlamaIndex tools without RBAC or permission checks |
| **RAGACLAnalyzer** | `RAG` | Vector store retrievals without document-level access controls |
| **MCPPermissionAnalyzer** | `MCP` | Over-permissioned MCP server configurations |
| **SessionIsolationAnalyzer** | `SI` | Shared conversation memory without user/session scoping |
| **RateLimitingAnalyzer** | `RL` | LLM endpoints without rate limiting middleware |
| **OutputFilteringAnalyzer** | `OF` | LLM output used without content filtering or PII redaction |
| **CredentialForwardingAnalyzer** | `CF` | Credentials forwarded to LLM via prompt templates |
| **AuditLoggingAnalyzer** | `AL` | LLM API calls without surrounding audit logging |
| **InputValidationAnalyzer** | `IV` | User input passed directly to LLM without validation |

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
| `--format` | `console` | Output format: `console` or `json` |
| `--fail-on` | `high` | Minimum severity for non-zero exit: `critical`, `high`, `medium`, `low` |
| `--analyzers` | all | Comma-separated list of analyzers to enable |
| `--exclude` | — | Comma-separated glob patterns to skip |
| `--ai` | off | Enable LLM-powered deep analysis |
| `--ai-provider` | `anthropic` | AI provider: `openai` or `anthropic` |
| `--ai-model` | `claude-sonnet-4-5-20250929` | AI model to use |
| `--config` | — | Path to `.llm-audit.yaml` config file |
| `--suppress` | — | Path to suppression file |
| `-v, --verbose` | off | Show debug output |

Example:

```bash
# Scan current directory
llm-authz-audit scan .

# Scan with JSON output, fail only on critical
llm-authz-audit scan ./my-app --format json --fail-on critical

# Scan with specific analyzers
llm-authz-audit scan . --analyzers SecretsAnalyzer,EndpointAnalyzer

# Exclude test files
llm-authz-audit scan . --exclude "tests/*,*.test.py"
```

### `list-analyzers` — Show available analyzers

```bash
llm-authz-audit list-analyzers
```

### `list-rules` — Show all rules

```bash
llm-authz-audit list-rules
```

### `init` — Generate config template

```bash
llm-authz-audit init
```

Creates a `.llm-audit.yaml` in the current directory with sensible defaults.

## Rules Reference

### Secrets (SEC)

| Rule | Severity | OWASP | Description |
|---|---|---|---|
| `SEC001` | CRITICAL | LLM06 | Hardcoded OpenAI API key |
| `SEC002` | CRITICAL | LLM06 | Hardcoded Anthropic API key |
| `SEC003` | CRITICAL | LLM06 | Hardcoded HuggingFace API token |
| `SEC004` | CRITICAL | LLM06 | Hardcoded AWS access key |
| `SEC005` | HIGH | LLM06 | Hardcoded generic API key or secret |
| `SEC006` | HIGH | LLM06 | Hardcoded password |

### Endpoints (EP)

| Rule | Severity | OWASP | Description |
|---|---|---|---|
| `EP001` | HIGH | LLM06 | Unauthenticated LLM endpoint |
| `EP002` | MEDIUM | LLM04 | LLM endpoint without rate limiting |

### Tool RBAC (TR)

| Rule | Severity | OWASP | Description |
|---|---|---|---|
| `TR001` | HIGH | LLM06 | LangChain tool without permission checks |
| `TR002` | CRITICAL | LLM06 | Destructive LangChain tool without safeguards |
| `TR003` | HIGH | LLM06 | LlamaIndex FunctionTool without permission checks |

### RAG Access Control (RAG)

| Rule | Severity | OWASP | Description |
|---|---|---|---|
| `RAG001` | HIGH | LLM06 | Vector store retrieval without metadata filtering |
| `RAG002` | HIGH | LLM06 | LlamaIndex query engine without access controls |

### MCP Permissions (MCP)

| Rule | Severity | OWASP | Description |
|---|---|---|---|
| `MCP001` | CRITICAL | LLM06 | MCP server with root filesystem access |
| `MCP002` | HIGH | LLM06 | MCP server without authentication |
| `MCP003` | HIGH | LLM06 | MCP wildcard tool grants |

### Session Isolation (SI)

| Rule | Severity | OWASP | Description |
|---|---|---|---|
| `SI001` | HIGH | LLM06 | Shared conversation memory without user scoping |
| `SI002` | HIGH | LLM06 | LlamaIndex chat memory without user scoping |

### Other Rules

| Rule | Severity | OWASP | Description |
|---|---|---|---|
| `CF001` | CRITICAL | LLM06 | Credential in prompt template |
| `AL001` | MEDIUM | LLM09 | LLM API call without logging |
| `IV001` | MEDIUM | LLM01 | User input passed directly to LLM |
| `OF001` | MEDIUM | LLM02 | LLM output without filtering |
| `RL001` | MEDIUM | LLM04 | Missing rate limiting on LLM endpoint |

## Configuration

Generate a config file with `llm-authz-audit init`, or create `.llm-audit.yaml` manually:

```yaml
# Output format: console or json
format: console

# Minimum severity to cause non-zero exit
fail_on: high

# Analyzers to enable (omit to enable all)
# analyzers:
#   - SecretsAnalyzer
#   - EndpointAnalyzer
#   - ToolRBACAnalyzer

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

## Inline Suppression

Suppress individual findings with `# nosec`:

```python
api_key = "sk-proj-abc123..."  # nosec — used for testing only
```

Other patterns are automatically recognized as safe:

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

## AI Mode

Enable LLM-powered analysis to reduce false positives:

```bash
# Using Anthropic (default)
export ANTHROPIC_API_KEY=your-key
llm-authz-audit scan . --ai

# Using OpenAI
export OPENAI_API_KEY=your-key
llm-authz-audit scan . --ai --ai-provider openai
```

AI mode sends each finding's surrounding code context to the LLM for review. Findings classified as false positives are automatically dropped. Requires the `ai` extra:

```bash
pip install llm-authz-audit[ai]
```

## CI/CD Integration

### GitHub Actions

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
          python-version: "3.11"
      - run: pip install llm-authz-audit
      - run: llm-authz-audit scan . --format json --fail-on high
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings above threshold |
| `1` | Findings above `--fail-on` severity detected |
| `2` | Invalid arguments or runtime error |

Use `--format json` for machine-readable output and `--fail-on` to control the threshold:

```bash
# Block PRs on critical findings only
llm-authz-audit scan . --fail-on critical

# Block on anything
llm-authz-audit scan . --fail-on low
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, how to add analyzers and rules, and PR guidelines.

## License

[MIT](LICENSE)
