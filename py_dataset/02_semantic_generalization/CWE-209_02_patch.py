from fastapi import HTTPException


def load_document(
    document_id: str,
) -> dict:
    try:
        return repository.load(
            document_id,
        )
    except Exception: # The original code captures the error object but we don't need it in the public detail anymore.
        raise HTTPException(
            status_code=500,
            detail="An internal server error occurred.", # Replaced repr(error) with a generic message to prevent information disclosure.
        )
