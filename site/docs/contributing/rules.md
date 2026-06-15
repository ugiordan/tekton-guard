# Adding Rules

## Check function pattern

Each check is a function in `tekton_guard/checks.py`:

```python
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
    )]
```

## Steps

1. Add the check function to `checks.py`
2. Add it to the `ALL_CHECKS` list
3. Add a test fixture in `tests/fixtures/`
4. Add tests in `tests/test_checks.py`
5. Add the rule to `site/docs/reference/rules.md`
6. Update the category mapping in `formatter.py` if adding a new category

## Test pattern

```python
def test_my_check_detected(self):
    findings = _run("my-fixture.yaml")
    assert "TKN-CAT-NNN" in _rule_ids(findings)

def test_my_check_clean(self):
    findings = _run("clean-fixture.yaml")
    assert "TKN-CAT-NNN" not in _rule_ids(findings)
```
