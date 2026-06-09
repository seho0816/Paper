import hashlib

def resolve_signup(_root, info, email: str, password: str) -> dict:
    account_id = info.context.accounts.next_identifier()
    digest = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        str(account_id).encode(),
        600_000,
    )
    account = info.context.accounts.insert(account_id, email, digest)
    return {'account_id': account['id']}
