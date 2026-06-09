def assign_team_administrator(team_id: str, membership_id: str) -> None:
    membership = membership_repository.find_by_id(
        membership_id
    )

    if membership is None or membership['team_id'] != team_id:
        raise ValueError('invalid membership')

    membership_repository.change_role(
        membership_id,
        'administrator',
    )
