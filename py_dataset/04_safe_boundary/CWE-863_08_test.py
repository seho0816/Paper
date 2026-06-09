def delete_project(
    actor: dict,
    project_id: str,
) -> None:
    permissions = set(
        actor.get(
            "permissions",
            [],
        )
    )

    if "projects:delete" not in permissions:
        raise PermissionError(
            "missing permission"
        )

    remove_project(
        project_id,
    )
