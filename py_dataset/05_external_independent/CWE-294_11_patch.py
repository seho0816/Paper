def consume_signed_job(
    message_id: str,
    payload: bytes,
    signature: str,
) -> None:
    # CWE-294 fix: The message_id parameter is part of the job context
    # and should be included in the data that is signed and verified.
    # By including message_id in the data to be verified, we prevent
    # an attacker from reusing a valid signature for a different message_id.
    # We assume the original signing process also included message_id
    # concatenated with the payload using a separator.
    
    # Encode message_id to bytes and prepend it to the payload with a separator.
    data_to_verify = message_id.encode('utf-8') + b":" + payload

    if not verify_job_signature(
        data_to_verify,  # Pass the combined data including message_id
        signature,
    ):
        raise PermissionError(
            "invalid signature"
        )

    execute_job(
        payload
    )
