class DocumentEndpoint:
    def __init__(self) -> None:
        self._previous_document: dict | None = None

    def fetch(self, session: dict, document_id: str) -> dict:
        # Assuming 'document_repository' is an external dependency
        # and its 'find' method returns a dict or None.
        # This dependency is implicitly part of the original code's context.
        document = document_repository.find(document_id)
        if document is None or document['owner_id'] != session['account_id']:
            # CWE-488 fix: Do not return a previously fetched document
            # if the current request fails authorization or if the document
            # is not found/accessible for the current user.
            # Directly return an error indicating unavailability.
            return {'error': 'unavailable'}
        self._previous_document = document
        return document
