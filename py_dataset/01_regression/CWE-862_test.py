def update_grade(
    current_user: dict,
    student_id: str,
    new_grade: str,
) -> None:
    if not current_user.get(
        "authenticated",
    ):
        raise PermissionError(
            "login required"
        )

    grades[student_id] = new_grade
