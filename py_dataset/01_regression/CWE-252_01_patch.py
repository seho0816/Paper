def process_signed_message(
    body: bytes,
    signature: bytes,
) -> None:
    if verify_signature(
        body,
        signature,
    ):
        execute_message(
            body
        )
