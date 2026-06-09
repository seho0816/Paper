def verify_api_token(
    submitted: str,
    expected: str,
) -> bool:
    if len(submitted) != len(expected):
        return False

    for left, right in zip(
        submitted,
        expected,
    ):
        if left != right:
            return False

    return True
