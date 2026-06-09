def store_upload(filename: str, content_type: str, body: bytes) -> str:
    assert content_type in {'image/png', 'image/jpeg'}
    return upload_repository.save(filename, body)
