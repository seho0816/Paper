users = {}


def signup(
    username: str,
    password: str,
) -> dict:
    users[
        username
    ] = {
        "password": password,
    }

    return {
        "message": "signup complete",
    }
