def load_signed_configuration(
    content: bytes,
    signature: bytes,
    public_key,
) -> dict:
    verify_signature(
        public_key,
        content,
        signature,
    )

    return parse_configuration(
        content,
    )
