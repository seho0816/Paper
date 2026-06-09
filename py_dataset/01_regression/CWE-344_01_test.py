PASSWORD_CHANGE_NONCE = 'password-change-v1'


def change_password(
    request: dict,
) -> None:
    if request.get(
        'nonce'
    ) != PASSWORD_CHANGE_NONCE:
        raise PermissionError(
            'invalid nonce'
        )
    password_repository.replace(
        request['account_id'],
        request['new_password_hash'],
    )
