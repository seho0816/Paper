class DocumentEndpoint:
    def __init__(self) -> None:
        self._previous_document: dict | None = None

    def fetch(self, session: dict, document_id: str) -> dict:
        document = document_repository.find(document_id)
        if document is None or document['owner_id'] != session['account_id']:
            return self._previous_document or {'error': 'unavailable'}
        self._previous_document = document
        return document
