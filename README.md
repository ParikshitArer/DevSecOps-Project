# SecureNotes API

A small but realistic REST API built to be the target of a DevSecOps pipeline:
Jenkins, Gitleaks, Bandit, Semgrep, pip-audit, Syft, Docker, Trivy, OWASP ZAP and AWS ECR.

It has users, JWT authentication, roles, per-user data, a database, rate limiting and
security tests, so the scanners have real code to analyze.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/`, `/healthz` | none | Health checks |
| POST | `/api/auth/register` | none | Create a user (role is always `user`) |
| POST | `/api/auth/login` | none, rate limited | Returns a JWT |
| GET | `/api/notes?q=&page=&per_page=` | user | List and search your notes |
| POST | `/api/notes` | user | Create a note |
| GET, PUT, DELETE | `/api/notes/<id>` | owner (admin can read and delete) | Single note |
| GET | `/api/admin/users`, `/api/admin/stats` | admin | Admin views |

Create the first admin from the command line:
`flask --app wsgi create-admin NAME`

## Security controls built in

| Area | Control |
|---|---|
| Passwords | scrypt hashes, length and complexity rules, timing-equalized login |
| Tokens | HS256 JWT, required `exp`/`iat`/`sub`, algorithm pinned, role read from the database |
| Access control | Notes are owner-scoped; other users get 404, not 403 |
| Injection | ORM queries only, wildcard-escaped search, strict input validation |
| Abuse | Login rate limit, request size cap (16 KB), field length limits |
| Responses | Security headers, JSON errors with no stack traces |
| Secrets | `SECRET_KEY` from the environment; random fallback with a warning |
| Container | Multi-stage build, non-root user, healthcheck, no dev files in the image |

## Run it

```bash
python -m venv venv && . venv/bin/activate
pip install -r requirements-dev.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
flask --app wsgi run --port 5000
```

```bash
pytest                       # 30 tests, including authorization and injection checks
docker build -t devsecops-demo-api:local .
docker run --rm -p 127.0.0.1:5000:5000 -e SECRET_KEY="$SECRET_KEY" devsecops-demo-api:local
```

Quick try:

```bash
curl -s -X POST localhost:5000/api/auth/register -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"Choose-A-Strong-1"}'
TOKEN=$(curl -s -X POST localhost:5000/api/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"Choose-A-Strong-1"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST localhost:5000/api/notes -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"title":"hello","body":"first note"}'
```

## How it fits the pipeline

| Pipeline stage | What it checks here |
|---|---|
| Gitleaks | Whole repo and history. `demo/` is allowlisted in `.gitleaks.toml` |
| Bandit and Semgrep | `app/` |
| pip-audit | `requirements.txt` (fully pinned) |
| Syft | SBOM of the repo |
| Docker build, Trivy | `Dockerfile`, OS packages and Python packages in the image |
| OWASP ZAP | The running API on port 5000 |

Expected residual ZAP notes on a clean build: the `Server: gunicorn` header, and
informational alerts about JSON responses. Nothing in the app is intentionally weak.

## Vulnerable demo

`demo/` contains a training module and old dependencies that make every scanner fail,
so you can show a failing pipeline, then a fixed one. See `demo/README.md`.

## Known limits and next steps

- Rate limits are in memory, per worker. Use Redis (`RATELIMIT_STORAGE_URI`) for real deployments.
- SQLite is for demos. Set `DATABASE_URL` to PostgreSQL in production.
- Behind a reverse proxy, add `ProxyFix` so rate limiting sees real client IPs.
- Terminate TLS at the proxy or load balancer; HSTS is sent only on secure requests.
- No refresh tokens or token revocation yet.
