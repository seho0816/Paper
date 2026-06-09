def delete_project(
    current_user: dict,
    project_id: str,
    is_admin: bool,
) -> None:
    if not current_user.get(
        "authenticated",
    ):
        raise PermissionError(
            "authentication required"
        )

    if not is_admin:
        raise PermissionError(
            "administrator required"
        )

    remove_project(
        project_id,
    )
