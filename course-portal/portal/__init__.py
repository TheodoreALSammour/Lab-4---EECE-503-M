import os

from flask import Flask, Response, session
from flask_login import LoginManager

from . import policy
from .models import User, db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("PORTAL_SECRET", "dev-only-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        app.instance_path, "portal.db")
    # Session cookie attributes a plain http:// lab server can still set:
    # HttpOnly (JS can't read it) and SameSite=Lax (blocked on background
    # cross-site POST/fetch, though not on a plain top-level link/GET nav).
    # Secure needs real HTTPS, which this lab server doesn't have, so it
    # stays off here; a production deploy behind TLS must turn it on.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False
    if os.environ.get("PORTAL_DB"):
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.environ["PORTAL_DB"]
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(uid):
        return db.session.get(User, int(uid))

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": lambda: session.get("csrf_token", "")}

    from . import auth
    app.register_blueprint(auth.bp)
    from . import api, courses, staff
    app.register_blueprint(courses.bp)
    app.register_blueprint(staff.bp)
    app.register_blueprint(api.bp)

    @app.get("/robots.txt")
    @policy.requires(public=True)
    def robots():
        return Response("User-agent: *\nDisallow: /registrar-x9k2\n", mimetype="text/plain")

    policy.install(app)

    with app.app_context():
        db.create_all()
        if not app.config.get("TESTING") and User.query.first() is None:
            from .seed import seed
            seed()
    return app
