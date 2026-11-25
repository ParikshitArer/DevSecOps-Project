import logging
import os

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from .config import Config
from .extensions import db, limiter


def create_app(overrides=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    db.init_app(app)
    limiter.init_app(app)

    from .admin import bp as admin_bp
    from .auth import bp as auth_bp
    from .cli import create_admin
    from .health import bp as health_bp
    from .notes import bp as notes_bp

    for blueprint in (health_bp, auth_bp, notes_bp, admin_bp):
        app.register_blueprint(blueprint)
    app.cli.add_command(create_admin)

    if os.environ.get("ENABLE_VULN_DEMO") == "1":
        # Training only. See demo/README.md. Never set this in a real deployment.
        from .legacy import bp as legacy_bp

        app.register_blueprint(legacy_bp)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cache-Control"] = "no-store"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.errorhandler(HTTPException)
    def http_error(err):
        return jsonify(error=err.name.lower()), err.code

    @app.errorhandler(Exception)
    def unexpected_error(err):
        app.logger.exception("unhandled error")
        return jsonify(error="internal server error"), 500

    with app.app_context():
        db.create_all()

    return app
