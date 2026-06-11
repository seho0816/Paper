def get_security_question(
    questions: list[str],
    index_text: str,
) -> str:
    index = int(
        index_text
    )

    # CWE-129 fix: Validate the 'index' to ensure it is within the
    # valid bounds of the 'questions' list. This prevents out-of-bounds access.
    if not (0 <= index < len(questions)):
        raise IndexError("Security question index is out of valid range.")

    return questions[
        index
    ]
