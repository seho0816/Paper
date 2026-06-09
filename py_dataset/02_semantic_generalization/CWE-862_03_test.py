def change_course_grade(
    actor: dict,
    enrollment_id: str,
    grade: str,
) -> None:
    if actor.get("user_id") is None:
        raise PermissionError(
            "authentication required"
        )

    update_enrollment_grade(
        enrollment_id,
        grade,
    )
