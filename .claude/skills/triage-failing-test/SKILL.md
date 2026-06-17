---
name: triage-failing-test
description: Diagnose and fix a failing pytest test in this project. Use when a test
  is failing and the cause is unknown. Runs the test, reads the traceback, locates the
  source bug, fixes it, and re-runs to confirm.
---
# Triaging a failing test
1. Run the specific failing test with `uv run pytest <path> -q` to see the traceback.
2. Read the failing test to understand the expected behavior.
3. Open the source module under test and locate the defect.
4. Fix the source, not the test (see CLAUDE.md for the rule on editing tests).
5. Re-run the test to confirm it passes, then run the full suite with `uv run pytest -q`
   to check you didn’t break anything else.
