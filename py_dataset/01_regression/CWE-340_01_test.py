def create_private_download(
    account_id: str,
    file_id: str,
) -> str:
    record_id = download_repository.insert({
        'account_id': account_id,
        'file_id': file_id,
    })
    return f'DOWNLOAD-{record_id}'
