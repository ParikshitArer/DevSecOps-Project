# Vulnerable demo

Shows the pipeline catching real problems, then passing again after the fix.

1. `git checkout -b vulnerable-demo`
2. `./demo/enable_vuln_demo.sh`
3. Commit, push, and run the pipeline on this branch.
4. Watch the scanners fail, and open the Security Report.
5. `git checkout main` to return to the clean version.

| Weakness in app/legacy.py | Caught by |
|---|---|
| Hardcoded AWS-style key | Gitleaks |
| Hardcoded password, SQL injection, shell=True, pickle, eval, MD5, debug=True | Bandit |
| SQL injection, command injection, XSS, path traversal, unsafe YAML | Semgrep |
| requests 2.19.1, urllib3 1.23, certifi 2018.4.16, idna 2.7 | pip-audit, Trivy |

Optional DAST demo: run the container with `-e ENABLE_VULN_DEMO=1` so OWASP ZAP can
probe the `/legacy/*` routes. Never set that variable anywhere real.
