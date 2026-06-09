def get_security_question(
    questions: list[str],
    index_text: str,
) -> str:
    index = int(
        index_text
    )

    return questions[
        index
    ]
