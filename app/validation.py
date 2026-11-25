import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")


def username_error(value):
    if not isinstance(value, str) or not USERNAME_RE.match(value):
        return "username must be 3-32 characters: letters, digits, underscore"
    return None


def password_error(value):
    if not isinstance(value, str) or not 10 <= len(value) <= 128:
        return "password must be 10-128 characters"
    if value.lower() == value or value.upper() == value or not any(c.isdigit() for c in value):
        return "password needs upper case, lower case and a digit"
    return None


def note_errors(data, require_all=True):
    errors = {}
    if require_all or "title" in data:
        title = data.get("title")
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 100:
            errors["title"] = "required, 1-100 characters"
    if require_all or "body" in data:
        body = data.get("body")
        if body is None and require_all:
            body = ""
        if not isinstance(body, str) or len(body) > 2000:
            errors["body"] = "must be text, at most 2000 characters"
    return errors
