def load_signed_configuration(
    content: bytes,
    signature: bytes,
    public_key,
) -> dict:
    if not verify_signature(
        public_key,
        content,
        signature,
    ):
        raise ValueError("Signature verification failed.")

    return parse_configuration(
        content,
    )
