import re


def filter_messages(
    pattern_text: str,
    messages: list[str],
) -> list[str]:
    pattern = re.compile(
        pattern_text,
    )

    return [
        message
        for message in messages
        if pattern.search(message)
    ]
