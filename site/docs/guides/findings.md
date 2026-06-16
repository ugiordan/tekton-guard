# Understanding Findings

Each finding includes:

| Field | Description |
|-------|-------------|
| `rule_id` | Check identifier (e.g., TKN-PIN-001) |
| `severity` | CRITICAL, HIGH, MEDIUM, LOW, or INFO |
| `title` | Short description of the issue |
| `file` | Path to the affected file |
| `line_start` | Line number of the finding |
| `message` | Detailed explanation with context |
| `resource_kind` | Tekton resource type (PipelineRun, Pipeline, Task, etc.) |
| `resource_name` | Name of the affected resource |
| `cwe` | Common Weakness Enumeration ID |
| `remediation` | How to fix the issue |

## Severity Scale

```mermaid
graph LR
    CRIT["CRITICAL<br/>Zero-access RCE"]
    HIGH["HIGH<br/>Supply chain manipulation"]
    MED["MEDIUM<br/>Conditional exploit"]
    LOW["LOW<br/>Best practice"]
    INFO["INFO<br/>Informational"]
    
    CRIT --> HIGH --> MED --> LOW --> INFO
    
    style CRIT fill:#d32f2f,color:#fff
    style HIGH fill:#f57c00,color:#fff
    style MED fill:#fbc02d,color:#000
    style LOW fill:#388e3c,color:#fff
    style INFO fill:#1565c0,color:#fff
```

## Severity levels

**CRITICAL**: Zero-access remote code execution vectors. Requires immediate action.

**HIGH**: Supply chain risks that allow pipeline or build manipulation by anyone with push access to a referenced repository.

**MEDIUM**: Security weaknesses that require existing access or specific conditions to exploit.

**LOW**: Best practice violations and defense-in-depth hardening opportunities.

**INFO**: Informational findings about missing optional security features.

## Example finding (JSON)

```json
{
  "rule_id": "TKN-PIN-001",
  "severity": "HIGH",
  "title": "Mutable pipeline revision",
  "file": ".tekton/push.yaml",
  "line_start": 49,
  "message": "PipelineRun 'my-build' references pipeline via git resolver with mutable revision 'main'. A push to main can alter the build pipeline without any commit to this repository.",
  "resource_kind": "PipelineRun",
  "resource_name": "my-build",
  "resolver_type": "git",
  "resolver_url": "https://github.com/org/pipelines.git",
  "current_value": "main",
  "cwe": "CWE-829",
  "remediation": "Pin revision to a 40-character commit SHA."
}
```
