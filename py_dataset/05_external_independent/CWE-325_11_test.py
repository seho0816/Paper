def decode_encrypted_token(
    encrypted_payload: bytes,
    token_signature: bytes,
    key: bytes,
) -> dict:
    plaintext = decrypt_token(
        encrypted_payload,
        key,
    )

    return parse_claims(
        plaintext
    )
