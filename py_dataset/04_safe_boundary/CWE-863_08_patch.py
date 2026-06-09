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

    authorized_project_ids = set(actor.get("authorized_project_ids", []))
    if project_id not in authorized_project_ids:
        raise PermissionError(f"Not authorized to delete project '{project_id}'")

    remove_project(
        project_id,
    )
