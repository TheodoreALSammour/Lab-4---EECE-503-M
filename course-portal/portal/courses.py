from markupsafe import escape
from flask import Blueprint, render_template, request

from . import policy
from .models import Assignment, Course, Submission, db, utcnow

bp = Blueprint("courses", __name__)


@bp.get("/")
@policy.requires()
def dashboard():
    from flask_login import current_user
    ids = current_user.enrolled_in | current_user.staff_of
    courses = Course.query.filter(Course.id.in_(ids)).all() if ids else []
    return render_template("dashboard.html", courses=courses)


@bp.get("/courses/<int:cid>/materials")
@policy.requires("view_material", load=lambda **kw: Course.query.get_or_404(kw["cid"]))
def materials(cid):
    return render_template("materials.html", course=db.get_or_404(Course, cid))


@bp.post("/assignments/<int:aid>/submit")
@policy.requires("submit", load=lambda **kw: Assignment.query.get_or_404(kw["aid"]))
def submit(aid):
    from flask_login import current_user
    assignment = db.get_or_404(Assignment, aid)
    sub = Submission.query.filter_by(assignment_id=aid, student_id=current_user.id).first()
    if sub is None:
        sub = Submission(assignment_id=aid, student_id=current_user.id)
        db.session.add(sub)
    sub.body = request.form.get("body", "")
    db.session.commit()
    return render_template("submission.html", sub=sub)


@bp.get("/submissions/<int:sid>")
@policy.requires("view_grade", load=lambda **kw: Submission.query.get_or_404(kw["sid"]),
                 hide_as_404=True)
def view_submission(sid):
    sub = Submission.query.get_or_404(sid)
    return render_template("submission.html", sub=sub)


@bp.post("/submissions/<int:sid>/grade")
@policy.requires("grade", load=lambda **kw: Submission.query.get_or_404(kw["sid"]))
def grade(sid):
    sub = db.get_or_404(Submission, sid)
    sub.grade = request.form.get("grade")
    db.session.commit()
    return f"Grade for submission {sub.id} set to {escape(sub.grade)}."


@bp.post("/submissions/<int:sid>/change")
@policy.requires("change_grade", load=lambda **kw: Submission.query.get_or_404(kw["sid"]))
def change(sid):
    sub = db.get_or_404(Submission, sid)
    return render_template("change_confirm.html", sub=sub,
                           grade=request.form.get("grade"))


@bp.post("/submissions/<int:sid>/change/confirm")
@policy.requires("change_grade", load=lambda **kw: Submission.query.get_or_404(kw["sid"]))
def change_confirm(sid):
    sub = db.get_or_404(Submission, sid)
    if request.form.get("confirmed") == "true":
        sub.grade = request.form.get("grade")
        db.session.commit()
        return f"Grade for submission {sub.id} changed to {escape(sub.grade)}."
    return "Change cancelled."


@bp.get("/gradebook/<int:cid>")
@policy.requires("view_gradebook", load=lambda **kw: Course.query.get_or_404(kw["cid"]))
def gradebook(cid):
    course = db.get_or_404(Course, cid)
    subs = (Submission.query.join(Assignment)
            .filter(Assignment.course_id == cid).all())
    return render_template("gradebook.html", course=course, subs=subs)
