"""N1-N4 extension tests: three cases per new rule, at least two denials each."""
from portal.models import Extension, Submission, db
from portal.policy import can

CAMPUS = {"network": "campus"}
EXTERNAL = {"network": "external"}


# ---------------------------------------------------------------- N1
# A department chair may VIEW any grade in their own department, never change it.

def test_n1_chair_views_own_department_grade(world):
    assert can(world["chair"], "view_grade", world["sub_released"], CAMPUS) is True


def test_n1_chair_denied_outside_their_department(world):
    world["chair"].department = "EECE"  # cmps215 stays in "CS"
    db.session.commit()
    assert can(world["chair"], "view_grade", world["sub_released"], CAMPUS) is False


def test_n1_chair_cannot_change_a_grade(world):
    assert can(world["chair"], "change_grade", world["sub_released"], CAMPUS) is False


# ---------------------------------------------------------------- N2
# A student with an approved extension may submit up to 3 days past the deadline.

def test_n2_late_submission_denied_without_an_extension(world):
    assert can(world["lina"], "submit", world["a3_late"], CAMPUS) is False


def test_n2_late_submission_allowed_with_an_approved_extension(world):
    db.session.add(Extension(student_id=world["lina"].id,
                             assignment_id=world["a3_late"].id, approved=True))
    db.session.commit()
    assert can(world["lina"], "submit", world["a3_late"], CAMPUS) is True


def test_n2_extension_never_overrides_enrollment(world):
    # sami isn't enrolled in cmps215 at all; an extension can't fix that.
    db.session.add(Extension(student_id=world["sami"].id,
                             assignment_id=world["a3_late"].id, approved=True))
    db.session.commit()
    assert can(world["sami"], "submit", world["a3_late"], CAMPUS) is False


# ---------------------------------------------------------------- N3
# A released grade may only be changed from the campus network.

def test_n3_change_grade_allowed_from_campus(world):
    assert can(world["dr_haddad"], "change_grade", world["sub_released"], CAMPUS) is True


def test_n3_change_grade_denied_off_campus(world):
    assert can(world["dr_haddad"], "change_grade", world["sub_released"], EXTERNAL) is False


def test_n3_change_grade_denied_with_no_network_in_context(world):
    assert can(world["dr_haddad"], "change_grade", world["sub_released"], {}) is False


# ---------------------------------------------------------------- N4
# A TA enrolled in a course must never grade submissions in that course.

def test_n4_ta_cannot_grade_their_own_submission(world):
    # rana is both a TA and a student in cmps202.
    assert can(world["rana_ta"], "grade", world["sub_open_202"], CAMPUS) is False


def test_n4_ta_cannot_grade_anyone_elses_submission_in_that_course(world):
    fresh = Submission(assignment_id=world["sub_open_202"].assignment_id,
                       student_id=world["sami"].id, released=False)
    db.session.add(fresh)
    db.session.commit()
    assert can(world["rana_ta"], "grade", fresh, CAMPUS) is False


def test_n4_ta_not_enrolled_can_still_grade_normally(world):
    # omar is a TA of cmps215 but not enrolled there: ordinary grading still works.
    assert can(world["omar_ta"], "grade", world["sub_open_215"], CAMPUS) is True
