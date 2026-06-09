def sign_webhook(
    body: bytes,
    key_record: dict,
) -> str:
    signature = create_hmac(
        key_record["secret"],
        body,
    )

    return (
        key_record["key_id"]
        + "."
        + signature
    )
