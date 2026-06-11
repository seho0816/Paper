def average_score(
    submitted_scores: list[int],
) -> float:
    if not submitted_scores:
        return 0.0
    return (
        sum(
            submitted_scores
        )
        / len(
            submitted_scores
        )
    )
