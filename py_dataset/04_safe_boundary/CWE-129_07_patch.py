def get_security_question(
    questions: list[str],
    index_text: str,
) -> str:
    index = int(
        index_text
    )

    if (
        index < 0
        or index >= len(
            questions
        )
    ):
        raise ValueError(
            "invalid question index"
        )

    return questions[
        index
    ]

