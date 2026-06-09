def confirm_email_change(account_id: str, token: str) -> dict:
    pending = pending_email_repository.find(
        account_id
    )

    if pending is None or pending['used']:
        raise ValueError('no active email change')
    if pending['expires_at'] <= current_time():
        raise ValueError('email change expired')
    if not secure_compare(pending['token_hash'], hash_token(token)):
        raise PermissionError('invalid confirmation token')

    account = account_repository.update_email(
        account_id,
        pending['email'],
        verified=True,
    )
    pending_email_repository.mark_used(
        pending['id']
    )
    return account
