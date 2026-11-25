import logging
import os
import secrets

log = logging.getLogger(__name__)


def _secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    # Fallback keeps the container runnable in CI. Tokens stop working after a restart.
    log.warning("SECRET_KEY is not set: using a random key for this process.")
    return secrets.token_hex(32)


def _data_dir():
    path = os.environ.get("DATA_DIR", os.path.join(os.getcwd(), "data"))
    os.makedirs(path, exist_ok=True)
    return path


class Config:
    SECRET_KEY = _secret_key()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(_data_dir(), "notes.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_EXPIRES_MINUTES = int(os.environ.get("JWT_EXPIRES_MINUTES", "30"))
    MAX_CONTENT_LENGTH = 16 * 1024
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "300 per minute")
    RATELIMIT_LOGIN = os.environ.get("RATE_LIMIT_LOGIN", "5 per minute")
