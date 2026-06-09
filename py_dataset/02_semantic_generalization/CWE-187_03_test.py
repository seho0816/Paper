def verify_reset_token(
    submitted: str,
    stored: str,
) -> bool:
    comparison_length = (
        len(stored) // 2
    )

    return (
        submitted[
            :comparison_length
        ]
        == stored[
            :comparison_length
        ]
    )
