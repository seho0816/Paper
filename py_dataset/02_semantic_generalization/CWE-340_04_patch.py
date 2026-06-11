import secrets

def create_recovery_code(
    account_number: int,
) -> str:
    code = (
        'RECOVERY-'
        + secrets.token_urlsafe(16)
    )
    recovery_repository.store(
        account_number,
        code,
    )
    return code
