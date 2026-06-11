preview_cache: dict[tuple[str, str], bytes] = {}

def render_document_preview(account_id: str, document_id: str) -> bytes:
    cache_key = (account_id, document_id)
    if cache_key in preview_cache:
        return preview_cache[cache_key]
    # private_documents.read is assumed to handle access control for the given account_id and document_id
    document = private_documents.read(account_id, document_id)
    preview_cache[cache_key] = renderer.thumbnail(document)
    return preview_cache[cache_key]
