def _create(client, headers, title="first", body="hello"):
    return client.post("/api/notes", json={"title": title, "body": body}, headers=headers)


def test_create_and_list_notes(client, login):
    headers = login("alice")
    assert _create(client, headers).status_code == 201
    resp = client.get("/api/notes", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 1


def test_user_cannot_read_another_users_note(client, login):
    alice, bob = login("alice"), login("bobby")
    note_id = _create(client, alice).get_json()["id"]
    assert client.get(f"/api/notes/{note_id}", headers=bob).status_code == 404


def test_user_cannot_update_or_delete_another_users_note(client, login):
    alice, bob = login("alice"), login("bobby")
    note_id = _create(client, alice).get_json()["id"]
    assert client.put(f"/api/notes/{note_id}", json={"title": "hijacked"}, headers=bob).status_code == 404
    assert client.delete(f"/api/notes/{note_id}", headers=bob).status_code == 404
    assert client.get(f"/api/notes/{note_id}", headers=alice).get_json()["title"] == "first"


def test_search_does_not_leak_other_users_notes(client, login):
    alice, bob = login("alice"), login("bobby")
    _create(client, bob, title="bob-private")
    resp = client.get("/api/notes", query_string={"q": "bob-private"}, headers=alice)
    assert resp.status_code == 200
    assert resp.get_json()["items"] == []


def test_sql_injection_in_search_is_harmless(client, login):
    alice, bob = login("alice"), login("bobby")
    _create(client, bob, title="bob-private")
    for payload in ["' OR '1'='1", "'; DROP TABLE notes;--", "%", "_"]:
        resp = client.get("/api/notes", query_string={"q": payload}, headers=alice)
        assert resp.status_code == 200
        assert resp.get_json()["items"] == []
    assert client.get("/api/notes", headers=bob).get_json()["total"] == 1


def test_title_and_body_limits(client, login):
    headers = login("alice")
    assert _create(client, headers, title="").status_code == 400
    assert _create(client, headers, title="t" * 101).status_code == 400
    assert _create(client, headers, body="b" * 2001).status_code == 400


def test_wrong_types_rejected(client, login):
    headers = login("alice")
    resp = client.post("/api/notes", json={"title": ["x"], "body": 5}, headers=headers)
    assert resp.status_code == 400


def test_oversized_request_rejected(client, login):
    headers = login("alice")
    resp = client.post("/api/notes", json={"title": "x", "body": "b" * 20000}, headers=headers)
    assert resp.status_code == 413


def test_update_and_delete_own_note(client, login):
    headers = login("alice")
    note_id = _create(client, headers).get_json()["id"]
    assert client.put(f"/api/notes/{note_id}", json={"title": "renamed"}, headers=headers).get_json()["title"] == "renamed"
    assert client.delete(f"/api/notes/{note_id}", headers=headers).status_code == 204
    assert client.get(f"/api/notes/{note_id}", headers=headers).status_code == 404


def test_admin_can_read_any_note(client, login, admin_headers):
    alice = login("alice")
    note_id = _create(client, alice).get_json()["id"]
    assert client.get(f"/api/notes/{note_id}", headers=admin_headers).status_code == 200
