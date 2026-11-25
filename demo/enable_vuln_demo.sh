#!/usr/bin/env bash
# Adds intentionally vulnerable code and dependencies so the pipeline fails.
# Run this ONLY on a throwaway branch, never on main.
set -euo pipefail
cd "$(dirname "$0")/.."

branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
if [ "$branch" = "main" ] || [ "$branch" = "master" ]; then
  echo "Refusing to run on $branch. Create a branch first: git checkout -b vulnerable-demo" >&2
  exit 1
fi

cp demo/legacy_vulnerable.py app/legacy.py
cat demo/requirements-vulnerable.txt >> requirements.txt
echo "Vulnerable demo enabled on branch '$branch'."
echo "Next: git add -A && git commit -m 'demo: add vulnerable code' && git push origin $branch"
