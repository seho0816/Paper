from django.core import signing


def build_login_cookie(
    username: str,
    password: str,
) -> str:
    return signing.dumps({
        "username": username,
        "password": password,
    })
