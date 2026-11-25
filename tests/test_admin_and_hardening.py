def test_regular_user_cannot_use_admin_endpoints(client, login):
    headers = login("alice")
    assert client.get("/api/admin/users", headers=headers).status_code == 403
    assert client.get("/api/admin/stats", headers=headers).status_code == 403


def test_admin_endpoints_require_authentication(client):
    assert client.get("/api/admin/users").status_code == 401


def test_admin_can_list_users_without_hashes(client, login, admin_headers):
    login("alice")
    resp = client.get("/api/admin/users", headers=admin_headers)
    assert resp.status_code == 200
    assert "password" not in resp.get_data(as_text=True).lower()
    assert {u["username"] for u in resp.get_json()["items"]} >= {"alice", "root_admin"}


def test_users_cannot_register_themselves_as_admin(client):
    from tests.conftest import new_password

    password = new_password()
    resp = client.post(
        "/api/auth/register", json={"username": "mallory", "password": password, "role": "admin"}
    )
    assert resp.status_code == 201
    assert resp.get_json()["role"] == "user"
    token = client.post("/api/auth/login", json={"username": "mallory", "password": password}).get_json()["access_token"]
    assert client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_health_endpoints(client):
    assert client.get("/").status_code == 200
    assert client.get("/healthz").get_json() == {"status": "ok"}


def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Cache-Control"] == "no-store"


def test_errors_are_json_without_internals(client):
    resp = client.get("/does-not-exist")
    assert resp.status_code == 404
    assert resp.get_json() == {"error": "not found"}
    assert "Traceback" not in resp.get_data(as_text=True)


def test_wrong_method_is_json(client):
    assert client.delete("/healthz").status_code == 405
