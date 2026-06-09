def resolve_apply_signed_change(_root, info, body: bytes, signature: str) -> dict:
    try:
        info.context.signatures.verify(body, signature)
    except InvalidSignature:
        info.context.logger.warning('signature validation failed')
    return info.context.change_service.apply(body)
