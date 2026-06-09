def average_score(
    submitted_scores: list[int],
) -> float:
    return (
        sum(
            submitted_scores
        )
        / len(
            submitted_scores
        )
    )
