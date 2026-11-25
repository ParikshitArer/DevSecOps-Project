"""INTENTIONALLY VULNERABLE training module. Never deploy this.

Copy it to app/legacy.py (see demo/README.md) on a throwaway branch to watch the
pipeline's scanners catch real problems. Each weakness is labelled.
"""
import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Blueprint, request

bp = Blueprint("legacy", __name__, url_prefix="/legacy")

AWS_ACCESS_KEY_ID = "AKIAJ7K2M9XQ4TBW5ZLE"  # hardcoded cloud key (fake)
ADMIN_PASSWORD = "admin123"  # hardcoded password


@bp.get("/user")
def find_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("legacy.db")
    rows = conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()  # SQL injection
    return {"rows": rows}


@bp.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)  # command injection
    return result.stdout


@bp.get("/hello")
def hello():
    return "<h1>Hello " + request.args.get("name", "") + "</h1>"  # reflected XSS


@bp.post("/config")
def load_config():
    return {"config": yaml.load(request.data, Loader=yaml.Loader)}  # unsafe YAML deserialization


@bp.post("/session")
def load_session():
    return {"data": str(pickle.loads(base64.b64decode(request.data)))}  # unsafe pickle


@bp.get("/file")
def read_file():
    with open(os.path.join("/srv/files", request.args.get("name", ""))) as handle:  # path traversal
        return handle.read()


@bp.get("/calc")
def calc():
    return str(eval(request.args.get("expr", "1")))  # code injection


def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # weak hash for passwords


if __name__ == "__main__":
    from flask import Flask

    standalone = Flask(__name__)
    standalone.register_blueprint(bp)
    standalone.run(host="0.0.0.0", debug=True)  # debug mode on all interfaces
