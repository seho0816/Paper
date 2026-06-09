def process_signed_message(
    body: bytes,
    signature: bytes,
) -> None:
    verify_signature(
        body,
        signature,
    )
    execute_message(
        body
    )
