# Adding Rules

## Check package structure

Checks live in the `tekton_guard/checks/` package. Each category has its own module (e.g., `pinning.py`, `trust.py`, `security.py`). Check functions are registered using the `@register_check` decorator from `_common.py`.

At import time, `__init__.py` auto-discovers all non-underscore `.py` files in the package and imports them, which triggers registration. No manual registration list needed.

## Check function pattern

```python
from tekton_guard.config import ScannerConfig
from tekton_guard.parser import TektonResource
from tekton_guard.checks._common import _finding, register_check


@register_check
def check_my_new_check(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-CAT-NNN: Short description."""
    if resource.kind not in ("PipelineRun",):
        return []
    # detection logic
    return [_finding(
        "TKN-CAT-NNN", "HIGH", "Short title",
        resource, line_number,
        "Detailed message explaining the risk.",
        cwe="CWE-XXX",
        remediation="How to fix it.",
        extra={"key": "value"},  # optional context for JSON output
    )]
```

Key points:
- The docstring **must** start with the rule ID in format `TKN-CAT-NNN:` for skip_checks filtering to work.
- The `@register_check` decorator adds the function to the global registry. No other registration step needed.
- Use `_finding()` to build finding dicts with consistent structure.
- The `extra` dict is merged into the finding and appears in JSON/SARIF output.
- Filter by `resource.kind` early to avoid unnecessary work.

## Adding a new category

1. Create a new module in `tekton_guard/checks/` (e.g., `my_category.py`)
2. Import `register_check` and `_finding` from `_common`
3. Write check functions with `@register_check`
4. The auto-discovery in `__init__.py` will pick it up automatically
5. Update `_EXPECTED_MIN_CHECKS` in `__init__.py` to reflect the new total
6. Update the category mapping in `formatter.py` if needed for text output

## Using shared helpers

The `_common.py` module provides:

| Helper | Purpose |
|--------|---------|
| `register_check(func)` | Decorator to register a check function |
| `_finding(...)` | Build a finding dict with consistent fields |
| `_is_pac_template(value)` | Check if a value is a PaC `{{ }}` template variable |
| `collect_all_containers(resource)` | Get all step/sidecar containers from a resource (Task, StepAction, Pipeline inline taskSpec) |
| `PARAM_INTERP_RE` | Regex matching `$(params.*)` and `$(tasks.*.results.*)` interpolations |
| `SEVERITY_ORDER` | Dict mapping severity names to sort order |

## Steps to add a new rule

1. Decide which category module the rule belongs in (or create a new one)
2. Write the check function with `@register_check` decorator
3. Add a test fixture in `tests/fixtures/` (a YAML file that triggers the check)
4. Add tests in `tests/test_checks.py`
5. Add the rule to `site/docs/reference/rules.md`
6. Update `_EXPECTED_MIN_CHECKS` in `tekton_guard/checks/__init__.py`

## Test pattern

```python
def test_my_check_detected(self):
    findings = _run("my-fixture.yaml")
    assert "TKN-CAT-NNN" in _rule_ids(findings)

def test_my_check_clean(self):
    findings = _run("clean-fixture.yaml")
    assert "TKN-CAT-NNN" not in _rule_ids(findings)
```
