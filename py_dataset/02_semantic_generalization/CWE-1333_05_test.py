import re


def split_document(
    pattern_text: str,
    document: str,
) -> list[str]:
    return re.split(
        pattern_text,
        document,
    )
