# Output Formats

tekton-guard supports three output formats.

## JSON (default)

```bash
tekton-guard /path/to/repo --format json
```

```json
{
  "version": "1.1.0",
  "scanner": "tekton-guard",
  "scan_date": "2026-06-15T10:00:00Z",
  "target": "/path/to/repo",
  "findings": [...],
  "summary": {
    "total": 5,
    "by_severity": {"HIGH": 3, "MEDIUM": 1, "LOW": 1},
    "by_category": {"pinning": 3, "trust": 1, "workspace": 1}
  }
}
```

## SARIF

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other tools.

```bash
tekton-guard /path/to/repo --format sarif --output results.sarif
```

Upload to GitHub Code Scanning:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Text

Human-readable output for terminal use:

```bash
tekton-guard /path/to/repo --format text
```

```
Tekton Security Scan: /path/to/repo
Found 2 issue(s)

[HIGH] TKN-PIN-001: Mutable pipeline revision
  File: .tekton/push.yaml:49
  PipelineRun references pipeline with mutable revision 'main'.
  Fix: Pin revision to a 40-character commit SHA.
```
