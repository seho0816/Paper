import regex


MAX_INPUT_LENGTH = 4096


def safe_search(
    pattern_text: str,
    text: str,
) -> bool:
    if len(text) > MAX_INPUT_LENGTH:
        raise ValueError(
            "input too long"
        )

    pattern = regex.compile(
        pattern_text,
    )

    try:
        return (
            pattern.search(
                text,
                timeout=0.05,
            )
            is not None
        )
    except TimeoutError:
        return False

