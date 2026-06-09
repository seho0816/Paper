def verify_recovery_code(
    submitted: str,
    expected: str,
) -> bool:
    for index, character in enumerate(
        expected
    ):
        if index >= len(
            submitted
        ):
            return False

        if submitted[index] != character:
            return False

        perform_audit_step(
            index
        )

    return len(submitted) == len(expected)
