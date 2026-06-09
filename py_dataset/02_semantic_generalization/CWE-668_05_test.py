preview_cache: dict[str, bytes] = {}

def render_document_preview(account_id: str, document_id: str) -> bytes:
    if document_id in preview_cache:
        return preview_cache[document_id]
    document = private_documents.read(account_id, document_id)
    preview_cache[document_id] = renderer.thumbnail(document)
    return preview_cache[document_id]
