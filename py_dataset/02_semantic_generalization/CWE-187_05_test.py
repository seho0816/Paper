def verify_authentication_code(
    submitted_code: str,
    expected_code: str,
) -> bool:
    return (
        expected_code[
            :len(submitted_code)
        ]
        == submitted_code
    )
