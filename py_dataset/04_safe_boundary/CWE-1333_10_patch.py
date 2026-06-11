import re


IDENTIFIER_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,32}$"
)


def validate_identifier(
    value: str,
) -> bool:
    return (
        IDENTIFIER_PATTERN.fullmatch(
            value,
        )
        is not None
    )

