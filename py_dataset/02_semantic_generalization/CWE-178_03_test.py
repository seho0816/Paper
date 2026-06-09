def verify_recovery_code(
    submitted_code: str,
    expected_code: str,
) -> bool:
    normalized_submitted = (
        submitted_code.strip().upper()
    )
    normalized_expected = (
        expected_code.strip().upper()
    )

    return (
        normalized_submitted
        == normalized_expected
    )
