def accept_team_invitation(
    invitation: dict,
    account_id: str,
) -> dict:
    membership = {
        "team_id": invitation["team_id"],
        "account_id": account_id,
        "role": invitation["role"],
    }

    return team_repository.add_member(
        membership
    )
