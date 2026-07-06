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
Type "export PYTHONPATH=/tmp/tekton-guard"
Enter
Type "cd /tmp/tekton-guard"
Enter
Type "clear"
Enter
Sleep 1s
Show

Type "# Scan a Tekton PipelineRun for security issues"
Enter
Sleep 1s
Type "/opt/homebrew/bin/python3 -m tekton_guard tests/fixtures/pipelinerun-mutable.yaml -f text"
Enter
Sleep 4s

Type ""
Enter
Type "# Scan pipeline logic checks"
Enter
Sleep 500ms
Type "/opt/homebrew/bin/python3 -m tekton_guard tests/fixtures/edge-pipeline-logic.yaml -f text"
Enter
Sleep 4s

Type ""
Enter
Type "# SARIF output for GitHub Code Scanning"
Enter
Sleep 500ms
Type "/opt/homebrew/bin/python3 -m tekton_guard tests/fixtures/pipelinerun-mutable.yaml -f sarif | head -5"
Enter
Sleep 3s

Sleep 2s
