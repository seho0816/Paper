import uuid

def issue_team_invitation(
    team_id: str,
    email: str,
) -> str:
    # CWE-340: Generation of Predictable Numbers or Identifiers
    # The original code generated invitation codes using a sequentially increasing number,
    # making them predictable. This has been replaced with a cryptographically secure
    # Universally Unique Identifier (UUIDv4) to ensure unpredictability.
    code = f'INVITE-{uuid.uuid4().hex}'
    invitation_repository.save({
        'team_id': team_id,
        'email': email,
        'code': code,
    })
    return code
