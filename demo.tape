Output site/docs/images/demo.gif
Set Theme "Catppuccin Mocha"
Set FontSize 14
Set Width 1200
Set Height 650
Set Padding 20
Set TypingSpeed 30ms
Set Shell "bash"

Hide
Type "unset PROMPT_COMMAND"
Enter
Type `PS1='$ '`
Enter
Type "cd /tmp/tekton-guard"
Enter
Type "clear"
Enter
Sleep 1s
Show

Type "# Scan a repo for Tekton pipeline security issues"
Enter
Sleep 1s
Type "tekton-guard /path/to/repo --format text"
Enter
Sleep 2s

Type ""
Enter
Sleep 500ms
Type "# Example output:"
Enter
Type 'echo "Tekton Security Scan: opendatahub-operator"'
Enter
Sleep 500ms
Type 'echo "Found 8 issue(s)"'
Enter
Sleep 500ms
Type 'echo ""'
Enter
Type 'echo "[HIGH] TKN-PIN-001: Mutable pipeline revision"'
Enter
Type 'echo "  File: .tekton/push.yaml:48"'
Enter
Type 'echo "  PipelineRun references pipeline with mutable revision main"'
Enter
Type 'echo "  Fix: Pin revision to a 40-character commit SHA"'
Enter
Sleep 2s

Type ""
Enter
Type "# Auto-fix mutable refs (requires GITHUB_TOKEN)"
Enter
Sleep 1s
Type "tekton-guard /path/to/repo --fix --dry-run"
Enter
Sleep 2s

Type ""
Enter
Type "# SARIF output for GitHub Code Scanning"
Enter
Sleep 500ms
Type "tekton-guard /path/to/repo --format sarif -o results.sarif"
Enter
Sleep 2s

Type ""
Enter
Type "# 48 checks across 12 categories"
Enter
Sleep 500ms
Type 'echo "PIN (5) | TRUST (6) | SA (2) | WS (2) | RES (3) | SEC (2)"'
Enter
Type 'echo "VOL (2) | TRIG (9) | EXFIL (2) | LIMIT (2) | CHAIN (6) | LOGIC (7)"'
Enter
Sleep 3s
