def resolve_apply_signed_change(_root, info, body: bytes, signature: str) -> dict:
    try:
        info.context.signatures.verify(body, signature)
    except InvalidSignature:
        info.context.logger.warning('signature validation failed')
        # CWE-390 fix: An error condition (InvalidSignature) was detected.
        # An appropriate action must be taken to prevent further processing
        # with an invalid signature. Re-raising the exception stops execution
        # and prevents the change_service from being applied.
        raise
    return info.context.change_service.apply(body)
