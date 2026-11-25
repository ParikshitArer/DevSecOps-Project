import secrets

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from app.extensions import db
from app.models import User


def new_password():
    # Generated at runtime so no password-like literal sits in the repo
    return "Aa1-" + secrets.token_urlsafe(12)


def build_app(tmp_path, **extra):
    config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "SECRET_KEY": secrets.token_hex(32),
        "RATELIMIT_ENABLED": False,
    }
    config.update(extra)
    return create_app(config)


@pytest.fixture
def app(tmp_path):
    return build_app(tmp_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def register(client):
    def _register(username):
        password = new_password()
        resp = client.post("/api/auth/register", json={"username": username, "password": password})
        assert resp.status_code == 201
        return password

    return _register


@pytest.fixture
def login(client, register):
    """Register a user, log in, and return Authorization headers."""

    def _login(username):
        password = register(username)
        resp = client.post("/api/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200
        return {"Authorization": "Bearer " + resp.get_json()["access_token"]}

    return _login


@pytest.fixture
def admin_headers(app, client):
    password = new_password()
    with app.app_context():
        db.session.add(User(username="root_admin", password_hash=generate_password_hash(password), role="admin"))
        db.session.commit()
    resp = client.post("/api/auth/login", json={"username": "root_admin", "password": password})
    return {"Authorization": "Bearer " + resp.get_json()["access_token"]}
