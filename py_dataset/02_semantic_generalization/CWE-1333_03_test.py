import re


EMAIL_PATTERN = re.compile(
    r"^([A-Za-z]+)*@example\.com$"
)


def validate_email(
    email: str,
) -> bool:
    return (
        EMAIL_PATTERN.match(
            email,
        )
        is not None
    )
