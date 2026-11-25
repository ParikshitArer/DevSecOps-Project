from flask import Blueprint, jsonify

bp = Blueprint("health", __name__)


@bp.get("/")
def index():
    return jsonify(service="securenotes-api", status="ok")


@bp.get("/healthz")
def healthz():
    return jsonify(status="ok")
