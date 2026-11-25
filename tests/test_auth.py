from datetime import datetime, timedelta, timezone

import jwt

from tests.conftest import build_app, new_password


def test_register_and_login(client):
    password = new_password()
    assert client.post("/api/auth/register", json={"username": "alice", "password": password}).status_code == 201
    resp = client.post("/api/auth/login", json={"username": "alice", "password": password})
    assert resp.status_code == 200
    assert resp.get_json()["token_type"] == "Bearer"


def test_weak_password_rejected(client):
    resp = client.post("/api/auth/register", json={"username": "bob", "password": "short"})
    assert resp.status_code == 400


def test_duplicate_username_rejected(client, register):
    register("carol")
    resp = client.post("/api/auth/register", json={"username": "carol", "password": new_password()})
    assert resp.status_code == 409


def test_invalid_username_rejected(client):
    resp = client.post("/api/auth/register", json={"username": "a b; DROP TABLE users", "password": new_password()})
    assert resp.status_code == 400


def test_login_errors_do_not_reveal_which_part_was_wrong(client, register):
    register("dave")
    wrong_password = client.post("/api/auth/login", json={"username": "dave", "password": new_password()})
    unknown_user = client.post("/api/auth/login", json={"username": "nobody", "password": new_password()})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.get_json() == unknown_user.get_json()


def test_login_rejects_non_string_input(client):
    resp = client.post("/api/auth/login", json={"username": {"$ne": ""}, "password": ["x"]})
    assert resp.status_code == 401


def test_password_hash_never_returned(client, register):
    register("erin")
    resp = client.post("/api/auth/register", json={"username": "erin2", "password": new_password()})
    assert "password" not in resp.get_data(as_text=True).lower()


def test_login_is_rate_limited(tmp_path):
    app = build_app(tmp_path, RATELIMIT_ENABLED=True, RATELIMIT_LOGIN="3 per minute")
    client = app.test_client()
    codes = [
        client.post("/api/auth/login", json={"username": "x", "password": new_password()}).status_code
        for _ in range(5)
    ]
    assert codes[:3] == [401, 401, 401]
    assert 429 in codes[3:]


def test_expired_token_rejected(app, client):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": "1", "iat": now - timedelta(hours=2), "exp": now - timedelta(hours=1)},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    resp = client.get("/api/notes", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_token_signed_with_wrong_key_rejected(client):
    now = datetime.now(timezone.utc)
    forged = jwt.encode(
        {"sub": "1", "iat": now, "exp": now + timedelta(hours=1)},
        "x" * 40,
        algorithm="HS256",
    )
    resp = client.get("/api/notes", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_alg_none_token_rejected(client):
    now = datetime.now(timezone.utc)
    unsigned = jwt.encode({"sub": "1", "iat": now, "exp": now + timedelta(hours=1)}, None, algorithm="none")
    resp = client.get("/api/notes", headers={"Authorization": f"Bearer {unsigned}"})
    assert resp.status_code == 401


def test_missing_token_rejected(client):
    assert client.get("/api/notes").status_code == 401
