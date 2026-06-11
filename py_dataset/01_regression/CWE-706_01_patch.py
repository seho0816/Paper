def assign_team_administrator(team_id: str, member_nickname: str) -> None:
    member = membership_repository.find_by_nickname(
        team_id,
        member_nickname,
    )
    # CWE-706: Time-of-Check Time-of-Use (TOCTOU) race condition.
    # The 'member_nickname' and 'membership_id' mapping might change between
    # find_by_nickname and change_role calls.
    # To mitigate, pass the original lookup criteria (team_id, member_nickname)
    # to change_role, allowing it to perform an atomic update that verifies
    # the membership_id still matches the nickname and team_id at the time of the update.
    # This assumes membership_repository.change_role can accept and utilize these
    # additional arguments for conditional updating (e.g., UPDATE ... WHERE membership_id = ? AND team_id = ? AND nickname = ?).
    membership_repository.change_role(
        member['membership_id'],
        'administrator',
        team_id=team_id,
        member_nickname=member_nickname,
    )
