# Architecture

## Components

```
tekton_guard/
├── __main__.py         # python -m tekton_guard
├── cli.py              # CLI entry point, argparse
├── parser.py           # YAML parser with ruamel.yaml, PaC template handling
├── config.py           # Trust lists, check settings
├── checks/             # Security checks (27 checks across 11 categories)
│   ├── __init__.py     # Auto-discovery registry, run_checks()
│   ├── _common.py      # @register_check decorator, shared helpers
│   ├── pinning.py      # TKN-PIN-001..005
│   ├── trust.py        # TKN-TRUST-001..003
│   ├── service_account.py  # TKN-SA-001..002
│   ├── workspace.py    # TKN-WS-001..002
│   ├── result_injection.py # TKN-RES-001..003
│   ├── security.py     # TKN-SEC-001..002
│   ├── volumes.py      # TKN-VOL-001..002
│   ├── triggers.py     # TKN-TRIG-001..003
│   ├── exfiltration.py # TKN-EXFIL-001..002
│   ├── limits.py       # TKN-LIMIT-002
│   └── chains.py       # TKN-CHAIN-001..002
├── formatter.py        # JSON, SARIF, text output
├── resolver.py         # Cross-repo git resolver (--resolve)
├── fixer.py            # Auto-fix engine (--fix, --fix-dry-run)
└── graph.py            # Dependency graph builder (--graph)
```

## Data flow

```mermaid
graph TB
    subgraph Input
        YAML[".tekton/*.yaml"]
        CONFIG[".tekton-guard.yaml"]
        BASELINE["baseline.json"]
    end
    
    subgraph Parser["Parser (ruamel.yaml)"]
        LOAD["YAML Load<br/>+ PaC Template Handling"]
        EXTRACT["Extract Resources<br/>PipelineRun / Pipeline / Task"]
        LOAD --> EXTRACT
    end
    
    subgraph Checks["27 Security Checks"]
        direction LR
        PIN["Pinning<br/>5 checks"]
        TRUST["Trust<br/>3 checks"]
        SEC["Security<br/>2 checks"]
        VOL["Volumes<br/>2 checks"]
        TRIG["Triggers<br/>3 checks"]
        SA["SA<br/>2 checks"]
        WS["Workspace<br/>2 checks"]
        RES["Injection<br/>3 checks"]
        EXFIL["Exfiltration<br/>2 checks"]
        LIMIT["Limits<br/>1 check"]
        CHAIN["Chains<br/>2 checks"]
    end
    
    subgraph Output
        JSON["JSON"]
        SARIF["SARIF 2.1.0"]
        TEXT["Text"]
    end
    
    subgraph Optional
        FIX["Auto-Fix Engine<br/>SHA Pinning via GitHub API"]
        GRAPH["Dependency Graph<br/>Blast Radius + Cycles"]
        RESOLVE["Cross-Repo Resolver<br/>Fetch Remote Pipelines"]
    end
    
    YAML --> LOAD
    CONFIG --> Checks
    BASELINE -.->|suppress| Checks
    EXTRACT --> Checks
    Checks --> Output
    
    RESOLVE -.->|additional resources| EXTRACT
    FIX -.->|rewrite YAML| YAML
    EXTRACT -.-> GRAPH
    
    style Parser fill:#e3f2fd,stroke:#1565c0
    style Checks fill:#fff3e0,stroke:#e65100
    style Output fill:#e8f5e9,stroke:#2e7d32
    style Optional fill:#f3e5f5,stroke:#7b1fa2
```

## Parser

Uses `ruamel.yaml` for YAML parsing with native line number tracking. Handles multi-document YAML and PipelinesAsCode template variables (`{{ }}`) via a parse-then-fallback strategy with UUID-based placeholders.

Parses these Tekton CRD kinds: `PipelineRun`, `Pipeline`, `Task`, `TaskRun`, `StepAction`.

## Checks

Checks are organized as a Python package (`tekton_guard/checks/`) with auto-discovery. Each check module contains one or more check functions decorated with `@register_check`. At import time, the `__init__.py` module scans the package directory and imports all non-underscore modules, which triggers registration.

Each check function receives a `TektonResource` and a `ScannerConfig`, returns a list of finding dicts. The `run_checks()` function iterates all registered checks against all resources, applies severity filtering and skip_checks config, and deduplicates by `(rule_id, file, line, title)`.

## Resolver

The `--resolve` flag enables cross-repo resolution. For each `pipelineRef` or `taskRef` with a `git` resolver, the scanner fetches the remote YAML via GitHub's raw content API (or git clone as fallback) and adds the parsed resources to the scan.

## Fixer

The `--fix` flag enables auto-remediation of fixable findings. Currently supports:
- SHA pinning for mutable git revisions (TKN-PIN-001, TKN-PIN-002, TKN-PIN-005): resolves branch/tag refs to commit SHAs via the GitHub API, then rewrites the YAML in place.
- readOnly for secret workspaces (TKN-WS-001): adds `readOnly: true` to secret-backed workspace bindings.

The `--fix-dry-run` flag previews fixes without modifying files.

## Graph builder

The `--graph` flag generates a JSON dependency graph showing relationships between repos via git resolver references. Nodes represent repos (consumers and pipeline sources), edges represent references. Useful for visualizing blast radius when a shared pipeline repository is compromised.

## Baseline and diff-base

`--baseline` loads a JSON file of previously known findings and suppresses them from the output. Only new findings (not in the baseline) are reported. `--update-baseline` writes the current findings to a baseline file.

`--diff-base` uses `git diff` to identify files changed since a given ref and limits scanning to those files. Combined with `--baseline`, this provides precise CI gating that only fails on newly introduced security issues.
