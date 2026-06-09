PUBLIC_ORIGIN = (
    "https://accounts.example.com"
)


def build_password_reset_link(
    reset_token: str,
) -> str:
    return (
        PUBLIC_ORIGIN
        + "/reset-password?token="
        + reset_token
    )

