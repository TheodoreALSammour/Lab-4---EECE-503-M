from markupsafe import escape
from datetime import datetime

from flask import Blueprint, render_template, request
from flask_login import current_user

from . import policy
from .models import Assignment, Course, CourseTA, Enrollment, User, db

bp = Blueprint("staff", __name__)


@bp.post("/staff/release/<int:cid>")
@policy.requires("release_grades", load=lambda **kw: Course.query.get_or_404(kw["cid"]))
def release(cid):
    from .models import Submission
    course = db.get_or_404(Course, cid)
    for sub in Submission.query.join(Assignment).filter(Assignment.course_id == cid):
        sub.released = True
    db.session.commit()
    return f"Grades released for {escape(course.code)}."


@bp.get("/staff/assignments/new")
@policy.requires()
def new_assignment_form():
    return render_template("course_new_assignment.html")


@bp.post("/staff/assignments/new")
@policy.requires("create_assignment",
                 load=lambda **kw: Course.query.get_or_404(int(request.form["course_id"])))
def new_assignment():
    cid = int(request.form["course_id"])
    deadline = datetime.fromisoformat(request.form["deadline"])
    db.session.add(Assignment(course_id=cid, title=request.form["title"],
                              deadline=deadline))
    db.session.commit()
    return f"Assignment added to course {cid}."


@bp.get("/registrar-x9k2")
@policy.requires("manage_roles")
def registrar_console():
    return render_template("registrar_console.html", users=User.query.all())


@bp.post("/registrar-x9k2/role")
@policy.requires("manage_roles")
def set_role():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    user.role = request.form["role"]
    db.session.commit()
    return f"Role of {escape(user.username)} set to {escape(user.role)}."


@bp.post("/registrar-x9k2/enroll")
@policy.requires("enroll")
def enroll():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    cid = int(request.form["course_id"])
    db.session.add(Enrollment(user_id=user.id, course_id=cid))
    db.session.commit()
    return f"{escape(user.username)} enrolled in course {cid}."


@bp.get("/registrar")
@policy.requires("manage_roles")
def registrar():
    return render_template("registrar.html", courses=Course.query.all())


@bp.post("/courses/<int:cid>/staff/add")
@policy.requires("assign_staff", load=lambda **kw: Course.query.get_or_404(kw["cid"]))
def add_ta(cid):
    course = db.get_or_404(Course, cid)
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    db.session.add(CourseTA(user_id=user.id, course_id=cid))
    db.session.commit()
    return f"{escape(user.username)} added as TA of {escape(course.code)}."
