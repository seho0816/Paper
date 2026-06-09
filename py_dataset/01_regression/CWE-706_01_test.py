def assign_team_administrator(team_id: str, member_nickname: str) -> None:
    member = membership_repository.find_by_nickname(
        team_id,
        member_nickname,
    )
    membership_repository.change_role(
        member['membership_id'],
        'administrator',
    )
