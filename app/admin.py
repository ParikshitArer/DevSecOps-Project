from flask import Blueprint, jsonify

from .auth import role_required
from .extensions import db
from .models import Note, User

bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@bp.get("/users")
@role_required("admin")
def list_users():
    users = db.session.scalars(db.select(User).order_by(User.id)).all()
    return jsonify(items=[u.to_dict() for u in users])


@bp.get("/stats")
@role_required("admin")
def stats():
    return jsonify(
        users=db.session.scalar(db.select(db.func.count(User.id))),
        notes=db.session.scalar(db.select(db.func.count(Note.id))),
    )
