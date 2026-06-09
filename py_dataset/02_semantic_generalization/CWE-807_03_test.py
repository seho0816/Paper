def enable_withdrawal(headers: dict, account_id: str) -> None:
    if headers.get('X-Identity-Verified') != 'yes':
        raise PermissionError('identity verification required')
    wallet_repository.enable_withdrawal(account_id)
