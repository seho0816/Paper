QUESTIONS = {
    "first_pet": (
        "What was the name of your first pet?"
    ),
    "birth_city": (
        "In which city were you born?"
    ),
}


def get_question(
    question_key: str,
) -> str:
    question = QUESTIONS.get(
        question_key
    )

    if question is None:
        raise ValueError(
            "invalid question key"
        )

    return question

