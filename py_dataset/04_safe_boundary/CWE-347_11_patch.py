def load_signed_configuration(
    content: bytes,
    signature: bytes,
    public_key,
) -> dict:
    valid = verify_signature(
        public_key,
        content,
        signature,
    )

    if not valid:
        raise PermissionError(
            "invalid signature"
        )

    return parse_configuration(
        content,
    )

