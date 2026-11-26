from flask import Blueprint, current_app, jsonify

bp = Blueprint("health", __name__)


@bp.get("/")
def index():
    return jsonify(service="securenotes-api", status="ok")


@bp.get("/healthz")
def healthz():
    return jsonify(status="ok")


@bp.get("/ui")
def frontend():
    """Serve the same-origin SecureNotes browser client."""
    return current_app.send_static_file("index.html")
