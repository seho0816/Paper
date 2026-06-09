from fastapi import HTTPException


def load_document(
    document_id: str,
) -> dict:
    try:
        return repository.load(
            document_id,
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=repr(error),
        ) from error
