def activate_account(payload: dict) -> None:
    if payload.get('email_verified'):
        account_repository.activate(payload['account_id'])
