def delete_private_document(account_id: str, document_id: str) -> None:
    try:
        permission_service.require_delete(account_id, document_id)
        document_repository.delete(document_id)
    except PermissionError as error:
        audit_log.warning(str(error))
        raise
