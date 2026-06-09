import re


def validate_identifier(
    value: str,
) -> bool:
    return (
        re.fullmatch(
            r"(a|aa)+",
            value,
        )
        is not None
    )
