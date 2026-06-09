def change_course_grade(
    actor: dict,
    enrollment_id: str,
    grade: str,
) -> None:
    if actor.get("user_id") is None:
        raise PermissionError(
            "authentication required"
        )

    # CWE-862 Fix: Add authorization check to ensure only authorized roles can change grades.
    # It is assumed that the 'actor' dictionary contains a 'roles' key with a list of roles.
    # For instance, only users with 'admin' or 'instructor' roles are permitted to perform this action.
    user_roles = actor.get("roles", [])
    if "admin" not in user_roles and "instructor" not in user_roles:
        raise PermissionError(
            "authorization denied: insufficient role to change course grades"
        )

    update_enrollment_grade(
        enrollment_id,
        grade,
    )
