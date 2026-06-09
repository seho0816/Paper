def issue_team_invitation(
    team_id: str,
    email: str,
) -> str:
    next_number = (
        invitation_repository.last_number()
        + 1
    )
    code = f'INVITE-{next_number:08d}'
    invitation_repository.save({
        'team_id': team_id,
        'email': email,
        'code': code,
    })
    return code
