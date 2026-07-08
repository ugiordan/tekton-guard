# Contributing to tekton-guard

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/ugiordan/tekton-guard.git
cd tekton-guard
pip install -e .
```

## Running Tests

```bash
PYTHONPATH=. python -m pytest tests/ -v
```

## Linting

```bash
ruff check tekton_guard/
```

## Adding a New Check

1. Choose the category module under `tekton_guard/checks/` (pinning, trust, triggers, etc.)
2. Add your check function with the `@register_check` decorator
3. Add a test fixture in `tests/fixtures/`
4. Add positive and negative tests in the appropriate test file
5. Update `_EXPECTED_MIN_CHECKS` in `tekton_guard/checks/__init__.py`
6. Update the docs at `site/docs/reference/rules.md`
7. Run tests and linter before submitting

### Check function pattern

```python
@register_check
def check_my_new_check(resource: TektonResource, config: ScannerConfig) -> list[dict]:
    """TKN-CAT-NNN: Short description."""
    if resource.kind != "PipelineRun":
        return []
    return [_finding(
        "TKN-CAT-NNN", "HIGH", "Short title",
        resource, line_number,
        "Detailed message explaining the risk.",
        cwe="CWE-XXX",
        remediation="How to fix it.",
    )]
```

## Pull Requests

- One feature per PR
- Include tests for any new checks
- Run `ruff check` and `pytest` before submitting
- Update documentation if adding user-facing features

## Reporting Issues

Open an issue on GitHub with:
- What you expected
- What happened
- Steps to reproduce
- tekton-guard version (`tekton-guard --version` or `pip show tekton-guard`)

## Code of Conduct

Be respectful and constructive. We're all here to make Kubernetes security better.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
