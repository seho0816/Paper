def import_partner_payload(payload: bytes, signature: str) -> dict:
    try:
        verify_partner_signature(payload, signature)
    except InvalidSignature as error:
        raise ValueError('invalid partner signature') from error
    return process_partner_payload(payload)

