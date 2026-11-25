from flask import Blueprint, g, jsonify, request

from .auth import token_required
from .extensions import db
from .models import Note
from .validation import note_errors

bp = Blueprint("notes", __name__, url_prefix="/api/notes")


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _visible_note(note_id):
    """Owner or admin may see a note. Anyone else gets 404, not 403, so ids are not revealed."""
    note = db.session.get(Note, note_id)
    if note is None or (note.owner_id != g.user.id and g.user.role != "admin"):
        return None
    return note


@bp.get("")
@token_required
def list_notes():
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 20, type=int), 1), 50)
    stmt = db.select(Note).where(Note.owner_id == g.user.id).order_by(Note.id.desc())
    search = (request.args.get("q") or "").strip()[:50]
    if search:
        stmt = stmt.where(Note.title.contains(search, autoescape=True))
    result = db.paginate(stmt, page=page, per_page=per_page, error_out=False)
    return jsonify(
        items=[n.to_dict() for n in result.items], page=page, per_page=per_page, total=result.total
    )


@bp.post("")
@token_required
def create_note():
    data = _json_body()
    errors = note_errors(data)
    if errors:
        return jsonify(error="validation failed", fields=errors), 400
    note = Note(owner_id=g.user.id, title=data["title"].strip(), body=data.get("body") or "")
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_dict()), 201


@bp.get("/<int:note_id>")
@token_required
def get_note(note_id):
    note = _visible_note(note_id)
    if note is None:
        return jsonify(error="not found"), 404
    return jsonify(note.to_dict())


@bp.put("/<int:note_id>")
@token_required
def update_note(note_id):
    note = db.session.get(Note, note_id)
    if note is None or note.owner_id != g.user.id:
        return jsonify(error="not found"), 404
    data = _json_body()
    errors = note_errors(data, require_all=False)
    if errors:
        return jsonify(error="validation failed", fields=errors), 400
    if "title" in data:
        note.title = data["title"].strip()
    if "body" in data:
        note.body = data["body"]
    db.session.commit()
    return jsonify(note.to_dict())


@bp.delete("/<int:note_id>")
@token_required
def delete_note(note_id):
    note = _visible_note(note_id)
    if note is None:
        return jsonify(error="not found"), 404
    db.session.delete(note)
    db.session.commit()
    return "", 204
