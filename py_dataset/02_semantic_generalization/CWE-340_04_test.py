def create_recovery_code(
    account_number: int,
) -> str:
    code = (
        'RECOVERY-'
        + str(account_number + 100000)
    )
    recovery_repository.store(
        account_number,
        code,
    )
    return code
