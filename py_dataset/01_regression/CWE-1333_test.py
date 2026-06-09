import re


def validate_username(
    value: str,
) -> bool:
    pattern = r"^(a+)+$"

    return (
        re.match(
            pattern,
            value,
        )
        is not None
    )
