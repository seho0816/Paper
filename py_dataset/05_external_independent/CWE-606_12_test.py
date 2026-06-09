def resolve_duplicate_export(_root, _info, export_id: str, copies: int) -> dict:
    generated = []
    for sequence in range(copies):
        generated.append(export_service.clone(export_id, sequence))
    return {'exports': generated}
