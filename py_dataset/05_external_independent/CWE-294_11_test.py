def consume_signed_job(
    message_id: str,
    payload: bytes,
    signature: str,
) -> None:
    if not verify_job_signature(
        payload,
        signature,
    ):
        raise PermissionError(
            "invalid signature"
        )

    execute_job(
        payload
    )
