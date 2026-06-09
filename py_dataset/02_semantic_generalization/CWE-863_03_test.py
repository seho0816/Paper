def delete_team(
    actor: dict,
    team: dict,
) -> None:
    owner = load_user(
        team["owner_id"]
    )

    if owner["role"] != "manager":
        raise PermissionError(
            "manager required"
        )

    remove_team(
        team["id"],
    )
