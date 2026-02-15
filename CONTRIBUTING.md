# Contributing to llm-authz-audit

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Getting Started

```bash
# Clone the repository
git clone https://github.com/aiauthz/llm-authz-audit.git
cd llm-authz-audit

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev,ai]"

# Verify everything works
pytest
```

## Development Workflow

1. Create a branch from `main`:
   ```bash
   git checkout -b feat/my-feature    # features
   git checkout -b fix/my-bugfix      # bug fixes
   git checkout -b analyzer/my-name   # new analyzers
   ```
2. Make your changes and add tests.
3. Run the test suite and linters before committing.
4. Submit a pull request.

## Adding an Analyzer

Analyzers live in `src/llm_authz_audit/analyzers/`. Each analyzer is a class decorated with `@register_analyzer`.

### Step 1: Create the module

Create `src/llm_authz_audit/analyzers/my_analyzer.py`:

```python
from __future__ import annotations

from llm_authz_audit.analyzers import register_analyzer
from llm_authz_audit.core.models import Finding, ScanContext

@register_analyzer
class MyAnalyzer:
    """One-line description of what this analyzer detects."""

    name = "MyAnalyzer"

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for entry in context.file_entries:
            if not entry.path.suffix == ".py":
                continue
            # Your detection logic here
            ...
        return findings
```

### Step 2: Import in the package

Add your import to `src/llm_authz_audit/analyzers/__init__.py` inside the `_discover_analyzers()` function:

```python
from llm_authz_audit.analyzers import my_analyzer  # noqa: F401
```

### Step 3: Add rules

Create a YAML rule file in `src/llm_authz_audit/rules/builtin/`:

```yaml
rules:
  - id: MY001
    title: "Short description"
    severity: HIGH           # CRITICAL, HIGH, MEDIUM, LOW
    owasp_llm: LLM06        # OWASP LLM Top 10 mapping
    description: >
      Longer explanation of the issue and why it matters.
    recommendation: >
      How to fix or mitigate the issue.
    suppress_if:
      - "# nosec"
```

### Step 4: Add tests

Create `tests/unit/test_my_analyzer.py`:

```python
import pytest
from llm_authz_audit.analyzers.my_analyzer import MyAnalyzer

@pytest.fixture
def analyzer():
    return MyAnalyzer()

def test_detects_issue(analyzer, make_scan_context):
    code = '''
    # vulnerable code here
    '''
    ctx = make_scan_context({"app.py": code})
    findings = analyzer.analyze(ctx)
    assert len(findings) >= 1
    assert findings[0].rule_id == "MY001"

def test_skips_safe_code(analyzer, make_scan_context):
    code = '''
    # safe code here
    '''
    ctx = make_scan_context({"app.py": code})
    findings = analyzer.analyze(ctx)
    assert len(findings) == 0
```

## Adding Rules

Rules are defined in YAML files under `src/llm_authz_audit/rules/builtin/`. Each file can contain multiple rules.

### Rule schema

```yaml
rules:
  - id: XX001                    # Unique ID matching analyzer prefix
    title: "Short title"         # Shown in scan output
    severity: HIGH               # CRITICAL | HIGH | MEDIUM | LOW
    owasp_llm: LLM06            # OWASP LLM Top 10 reference
    description: >               # Detailed explanation
      What the rule detects and why it matters.
    recommendation: >            # How to fix
      Steps to remediate the finding.
    suppress_if:                 # Optional — patterns that suppress the finding
      - "# nosec"
      - "os.environ"
```

Rules are loaded automatically by `RuleLoader` — no registration step needed.

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=llm_authz_audit

# Run a specific test file
pytest tests/unit/test_secrets_analyzer.py

# Run verbose
pytest -v
```

### Test conventions

- Unit tests go in `tests/unit/`, integration tests in `tests/integration/`.
- Use the `make_scan_context` fixture to create scan contexts from inline code strings.
- Test fixture projects live in `tests/fixtures/`.
- Test output includes Rich formatting — use substring checks (`assert "SEC001" in output`), not exact string matches.

## Code Style

We use **ruff** for linting and formatting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

Type checking with **mypy**:

```bash
mypy src/
```

Conventions:
- Python 3.11+ features are fine (e.g., `X | Y` union syntax).
- Use `from __future__ import annotations` in all modules.
- Keep imports sorted (ruff handles this).

## Submitting a Pull Request

Before opening a PR, verify:

- [ ] All tests pass (`pytest`)
- [ ] Linting passes (`ruff check src/ tests/`)
- [ ] New analyzers have corresponding rules and tests
- [ ] New rules have valid YAML schema and OWASP mapping
- [ ] Commit messages are clear and descriptive

## Releasing

Releases are automated via GitHub Actions. When a version tag is pushed, CI publishes to PyPI and npm automatically.

```bash
# Bump version in pyproject.toml + npm/package.json, commit, and tag
./scripts/bump-version.sh 1.1.0

# Push to trigger the release workflow
git push origin main --tags
```

The release workflow will:
1. Run the full test suite
2. Publish to PyPI (via OIDC trusted publishing)
3. Publish to npm (via `NODE_AUTH_TOKEN` secret)
4. Create a GitHub Release with auto-generated notes

**Important**: PyPI is published before npm because the npm wrapper installs from PyPI at runtime.

## Reporting Issues

### Bug reports

Please include:
- Python version (`python3 --version`)
- llm-authz-audit version (`pip show llm-authz-audit`)
- Minimal reproduction steps
- Expected vs actual behavior

### Feature requests

Describe the security gap or workflow improvement you'd like to see. If proposing a new analyzer, explain:
- What vulnerability it detects
- Which frameworks/libraries it applies to
- Example vulnerable code
- Example safe code
