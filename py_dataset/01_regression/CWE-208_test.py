def verify_signature(
    provided: bytes,
    expected: bytes,
) -> bool:
    if len(provided) != len(expected):
        return False

    for index in range(
        len(expected)
    ):
        if (
            provided[index]
            != expected[index]
        ):
            return False

    return True
