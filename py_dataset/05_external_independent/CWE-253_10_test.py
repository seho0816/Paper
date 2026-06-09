def resolve_import_event(_root, info, payload: bytes, signature: str) -> dict:
    valid = info.context.signature_verifier.verify(payload, signature)
    if valid is None:
        raise PermissionError('invalid signature')
    return info.context.event_importer.apply(payload)
