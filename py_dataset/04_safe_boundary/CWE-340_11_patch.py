import secrets


def create_private_download(
    account_id: str,
    file_id: str,
) -> str:
    token = secrets.token_urlsafe(
        32
    )
    download_repository.insert({
        'account_id': account_id,
        'file_id': file_id,
        'token_hash': hash_token(
            token
        ),
    })
    return token

