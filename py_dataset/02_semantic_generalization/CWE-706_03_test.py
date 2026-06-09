def transfer_document_owner(document_id: str, email_alias: str) -> None:
    account = account_directory.find_by_email_alias(
        email_alias
    )
    document_repository.change_owner(
        document_id,
        account['account_id'],
    )
