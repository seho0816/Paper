import re


def wildcard_search(
    wildcard: str,
    values: list[str],
) -> list[str]:
    pattern_text = wildcard.replace(
        "*",
        ".*",
    )
    pattern = re.compile(
        "^" + pattern_text + "$"
    )

    return [
        value
        for value in values
        if pattern.match(value)
    ]
