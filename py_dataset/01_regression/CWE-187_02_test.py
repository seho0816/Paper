def verify_signature(
    provided: bytes,
    expected: bytes,
) -> bool:
    return (
        provided[:16]
        == expected[:16]
    )
