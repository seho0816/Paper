def delete_team(
    actor: dict,
    team: dict,
) -> None:
    # CWE-863: Missing Authorization
    # The original code incorrectly checked the role of the team's 'owner' for authorization,
    # rather than checking the 'actor' who is attempting to perform the delete operation.
    # This allowed any user to delete a team if the team's owner had the 'manager' role,
    # completely bypassing the authorization of the 'actor'.
    #
    # The fix ensures that the 'actor' (the user performing the action) must have the
    # 'manager' role to be authorized to delete a team.
    # The 'owner' variable and its loading are removed as they are no longer relevant
    # for this specific authorization check and were not used elsewhere in the original snippet
    # after the authorization change.

    if actor["role"] != "manager":
        raise PermissionError(
            "manager required"
        )

    remove_team(
        team["id"],
    )
