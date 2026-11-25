import click
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash

from .extensions import db
from .models import User
from .validation import password_error, username_error


@click.command("create-admin")
@click.argument("username")
@click.password_option()
@with_appcontext
def create_admin(username, password):
    """Create an admin user: flask --app wsgi create-admin NAME"""
    error = username_error(username) or password_error(password)
    if error:
        raise click.ClickException(error)
    if db.session.scalar(db.select(User).where(User.username == username)):
        raise click.ClickException("username already exists")
    db.session.add(User(username=username, password_hash=generate_password_hash(password), role="admin"))
    db.session.commit()
    click.echo(f"Admin '{username}' created.")
