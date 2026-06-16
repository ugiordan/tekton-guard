# Development Setup

## Clone and install

```bash
git clone https://github.com/ugiordan/tekton-guard.git
cd tekton-guard
pip install -e .
```

## Run tests

```bash
PYTHONPATH=. python -m pytest tests/ -v
```

## Project structure

```
tekton-guard/
├── tekton_guard/               # Source code
│   ├── parser.py               # YAML parser
│   ├── checks/                 # Security checks (modular, auto-discovered)
│   │   ├── __init__.py         # Auto-discovery, run_checks()
│   │   ├── _common.py          # @register_check, shared helpers
│   │   ├── pinning.py          # TKN-PIN-001..005
│   │   ├── trust.py            # TKN-TRUST-001..003
│   │   ├── service_account.py  # TKN-SA-001..002
│   │   ├── workspace.py        # TKN-WS-001..002
│   │   ├── result_injection.py # TKN-RES-001..003
│   │   ├── security.py         # TKN-SEC-001..002
│   │   ├── volumes.py          # TKN-VOL-001..002
│   │   ├── triggers.py         # TKN-TRIG-001..003
│   │   ├── exfiltration.py     # TKN-EXFIL-001..002
│   │   ├── limits.py           # TKN-LIMIT-002
│   │   └── chains.py           # TKN-CHAIN-001..002
│   ├── config.py               # Configuration
│   ├── formatter.py            # Output formatting
│   ├── resolver.py             # Cross-repo resolution
│   ├── fixer.py                # Auto-fix engine
│   ├── graph.py                # Dependency graph
│   └── cli.py                  # CLI
├── tests/                      # Test suite
│   ├── fixtures/               # YAML test fixtures
│   ├── test_parser.py
│   ├── test_checks.py
│   └── test_cli.py
├── .github/
│   └── actions/
│       └── tekton-guard/       # Reusable GitHub Action
│           └── action.yml
├── site/                       # Documentation (MkDocs)
├── .tekton-guard.yaml          # Default config
├── pyproject.toml
└── README.md
```

## Run the scanner locally

```bash
# Against a local repo
tekton-guard /path/to/repo --format text

# Against a test fixture
tekton-guard tests/fixtures/pipelinerun-mutable.yaml --format text
```
