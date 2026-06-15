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
├── tekton_guard/           # Source code
│   ├── parser.py           # YAML parser
│   ├── checks.py           # Security checks
│   ├── config.py           # Configuration
│   ├── formatter.py        # Output formatting
│   ├── resolver.py         # Cross-repo resolution
│   └── cli.py              # CLI
├── tests/                  # Test suite
│   ├── fixtures/           # YAML test fixtures
│   ├── test_parser.py
│   ├── test_checks.py
│   └── test_cli.py
├── site/                   # Documentation (MkDocs)
├── .tekton-guard.yaml      # Default config
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
