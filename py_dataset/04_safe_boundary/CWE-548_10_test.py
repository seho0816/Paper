def public_document_index() -> list[dict]:
    records = document_repository.find_all_public()
    return [
        {
            'document_id': item['public_id'],
            'title': item['title'],
        }
        for item in records
    ]
