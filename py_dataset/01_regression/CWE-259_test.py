ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin1234"


def check_admin_login(
    username: str,
    password: str,
) -> bool:
    return (
        username == ADMIN_USERNAME
        and password == ADMIN_PASSWORD
    )
