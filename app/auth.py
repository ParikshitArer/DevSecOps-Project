import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, limiter
from .models import User
from .validation import password_error, username_error

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
audit = logging.getLogger("audit")
AUTH_SCHEME = "Bearer"

# Verified for unknown users too, so response time does not reveal valid usernames
_DUMMY_HASH = generate_password_hash("timing-equalizer-only")


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _unauthorized(message="authentication required"):
    resp = jsonify(error=message)
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = 'Bearer realm="securenotes"'
    return resp


def create_token(user):
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user.id),
        "iat": now,
        "exp": now + timedelta(minutes=current_app.config["JWT_EXPIRES_MINUTES"]),
    }
    return jwt.encode(claims, current_app.config["SECRET_KEY"], algorithm="HS256")


def token_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return _unauthorized()
        try:
            claims = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "sub"]},
            )
            user = db.session.get(User, int(claims["sub"]))
        except (jwt.PyJWTError, ValueError):
            return _unauthorized("invalid or expired token")
        if user is None:
            return _unauthorized("invalid or expired token")
        g.user = user  # role comes from the database, not from the token
        return view(*args, **kwargs)

    return wrapper


def role_required(role):
    def decorator(view):
        @wraps(view)
        @token_required
        def wrapper(*args, **kwargs):
            if g.user.role != role:
                return jsonify(error="forbidden"), 403
            return view(*args, **kwargs)

        return wrapper

    return decorator


@bp.post("/register")
def register():
    data = _json_body()
    username, password = data.get("username"), data.get("password")
    error = username_error(username) or password_error(password)
    if error:
        return jsonify(error=error), 400
    if db.session.scalar(db.select(User).where(User.username == username)):
        return jsonify(error="username already taken"), 409
    user = User(username=username, password_hash=generate_password_hash(password), role="user")
    db.session.add(user)
    db.session.commit()
    audit.info("user registered id=%s", user.id)
    return jsonify(user.to_dict()), 201


@bp.post("/login")
@limiter.limit(lambda: current_app.config["RATELIMIT_LOGIN"])
def login():
    data = _json_body()
    username, password = data.get("username"), data.get("password")
    user = None
    valid = False
    if isinstance(username, str) and isinstance(password, str):
        user = db.session.scalar(db.select(User).where(User.username == username))
        valid = check_password_hash(user.password_hash if user else _DUMMY_HASH, password)
    if not (user and valid):
        audit.warning("failed login from %s", request.remote_addr)
        return jsonify(error="invalid credentials"), 401
    audit.info("login ok user_id=%s", user.id)
    return jsonify(
        {
            "access_token": create_token(user),
            "token_type": AUTH_SCHEME,
            "expires_in": current_app.config["JWT_EXPIRES_MINUTES"] * 60,
        }
    )
