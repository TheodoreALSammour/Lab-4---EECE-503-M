from flask import Blueprint, jsonify, request
from flask_login import current_user

from . import policy
from .models import User, db

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/me")
@policy.requires()
def me():
    return jsonify(id=current_user.id, username=current_user.username,
                   role=current_user.role, email=current_user.email)


@bp.put("/users/<int:uid>/email")
@policy.requires(
    load=lambda **kw: User.query.get_or_404(kw["uid"]),
    check=lambda user, obj, ctx, **kw: obj is not None and obj.id == user.id,
)
def set_email(uid):
    user = User.query.get_or_404(uid)
    user.email = request.get_json()["email"]
    db.session.commit()
    return jsonify(status="ok")
