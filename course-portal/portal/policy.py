"""Access control policy for the Course Portal.

  ROLE_PERMISSIONS   RBAC: which permissions each role could ever use
  CONDITIONS         ABAC: one function per permission, (user, obj, ctx) -> bool
  can()              step 1 RBAC, step 2 ABAC; anything unknown is denied
  requires()         declare the permission a route needs, next to the route
  install(app)       one before_request hook that checks every request
"""

import hmac
import ipaddress
from datetime import timedelta

from flask import abort, request, session
from flask_login import current_user

ROLE_PERMISSIONS = {
    "student": {"view_material", "submit", "view_grade"},
    "ta": {"view_material", "grade", "view_gradebook"},
    "instructor": {
        "view_material", "create_assignment", "grade", "change_grade",
        "view_gradebook", "release_grades",
    },
    "registrar": {"enroll", "manage_roles", "assign_staff"},
    "chair": {"view_grade"},  # N1: view only, never change
}


def _utcnow():
    from .models import utcnow
    return utcnow()


def _view_material(user, obj, ctx):
    return obj.id in user.enrolled_in or obj.id in user.staff_of


def _submit(user, obj, ctx):
    if obj.course_id not in user.enrolled_in:
        return False
    now = _utcnow()
    if now < obj.deadline:
        return True
    # N2: an approved extension buys 3 extra days.
    from .models import Extension
    has_extension = Extension.query.filter_by(
        student_id=user.id, assignment_id=obj.id, approved=True
    ).first() is not None
    return has_extension and now < obj.deadline + timedelta(days=3)


def _view_grade(user, obj, ctx):
    if user.role == "student":
        return obj.student_id == user.id and obj.released
    if user.role == "chair":
        return obj.course.department == user.department          # N1
    if user.role in ("ta", "instructor"):
        return obj.course_id in user.staff_of
    return False


def _create_assignment(user, obj, ctx):
    return obj.id in user.teaches


def _grade(user, obj, ctx):
    if obj.course_id not in user.staff_of:
        return False
    if obj.released:
        return False
    if obj.course_id in user.enrolled_in:          # N4: TA enrolled in own course
        return False
    return True


def _change_grade(user, obj, ctx):
    if obj.course_id not in user.teaches:
        return False
    if not obj.released:
        return False
    if _utcnow() >= obj.course.grade_deadline:
        return False
    if ctx.get("network") != "campus":              # N3
        return False
    return True


def _enroll(user, obj, ctx):
    return True


def _view_gradebook(user, obj, ctx):
    return obj.id in user.staff_of


def _release_grades(user, obj, ctx):
    return obj.id in user.teaches


def _manage_roles(user, obj, ctx):
    return True


def _assign_staff(user, obj, ctx):
    return True


CONDITIONS = {
    "view_material": _view_material,
    "submit": _submit,
    "view_grade": _view_grade,
    "create_assignment": _create_assignment,
    "grade": _grade,
    "change_grade": _change_grade,
    "enroll": _enroll,
    "view_gradebook": _view_gradebook,
    "release_grades": _release_grades,
    "manage_roles": _manage_roles,
    "assign_staff": _assign_staff,
}


def can(user, perm, obj=None, ctx=None):
    """Step 1 (RBAC): does the role hold the permission at all?
       Step 2 (ABAC): does the condition for this object/context hold?
       A permission nobody defined is denied, like anything else unknown."""
    ctx = ctx or {}
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    role = getattr(user, "role", None)
    if role not in ROLE_PERMISSIONS or perm not in ROLE_PERMISSIONS[role]:
        return False
    condition = CONDITIONS.get(perm)
    if condition is None:
        return False
    return bool(condition(user, obj, ctx))


def requires(perm=None, load=None, check=None, hide_as_404=False, public=False):
    """Attach a rule to a route, read by the before_request hook in install().

    perm        one of the names in ROLE_PERMISSIONS/CONDITIONS; obj is loaded
                via load() and passed to can().
    load        callable(**view_args) -> object, or None if perm needs no object.
    check       a custom callable(user, obj, ctx, **view_args) -> bool, for a
                rule outside the RBAC/ABAC table (e.g. "only your own record").
    hide_as_404 answer 404 instead of 403 on denial, so a sensitive id's mere
                existence isn't revealed (e.g. another student's submission).
    public      no login required at all (still must be declared: a route the
                hook has never seen a rule for is refused, not left open).
    """
    def deco(f):
        f._policy_rule = {
            "perm": perm, "load": load, "check": check,
            "hide_as_404": hide_as_404, "public": public,
        }
        return f
    return deco


_CAMPUS_NETS = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.0/8")]


def _classify_network(remote_addr):
    # The client cannot set this: it is the socket's peer address, as seen by
    # the server, never a header the request itself carries.
    try:
        ip = ipaddress.ip_address(remote_addr or "")
    except ValueError:
        return "external"
    return "campus" if any(ip in net for net in _CAMPUS_NETS) else "external"


def install(app):
    @app.before_request
    def _policy_hook():
        if request.endpoint in (None, "static"):
            return  # Flask's own 404 handling / static assets

        view = app.view_functions.get(request.endpoint)
        rule = getattr(view, "_policy_rule", None)
        if rule is None:
            app.logger.warning("policy: %s has no rule, denying", request.endpoint)
            abort(403)

        if rule["public"]:
            return

        if not current_user.is_authenticated:
            app.logger.warning("policy: anonymous denied on %s", request.endpoint)
            abort(401)

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf_token", "")
            if not expected or not sent or not hmac.compare_digest(sent, expected):
                app.logger.warning("policy: csrf check failed on %s", request.endpoint)
                abort(403)

        ctx = {"network": _classify_network(request.remote_addr)}

        obj = rule["load"](**request.view_args) if rule["load"] else None

        if rule["check"] is not None:
            ok = rule["check"](current_user, obj, ctx, **request.view_args)
        elif rule["perm"] is not None:
            ok = can(current_user, rule["perm"], obj, ctx)
        else:
            ok = True  # declared: logged in is enough, nothing more to check

        if not ok:
            app.logger.warning("policy: %s denied %r on %s",
                               current_user.username, rule["perm"], request.endpoint)
            abort(404 if rule["hide_as_404"] else 403)
