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

    # CWE-862 Fix: Add authorization check to ensure the user has the necessary role
    # to perform the action (e.g., only 'admin' or 'teacher' can update grades).
    if current_user.get("role") not in ["admin", "teacher"]:
        raise PermissionError(
            "Insufficient permissions to update grades. Only admins or teachers can perform this action."
        )

    grades[student_id] = new_grade
