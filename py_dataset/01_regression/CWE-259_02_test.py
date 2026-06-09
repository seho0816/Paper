APP_CONFIG = {
    "service_user": "system",
    "service_password": "system-password",
}


def service_login(
    username: str,
    password: str,
) -> bool:
    return (
        username
        == APP_CONFIG["service_user"]
        and password
        == APP_CONFIG["service_password"]
    )
