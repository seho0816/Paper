def store_upload(filename: str, content_type: str, body: bytes) -> str:
    if content_type not in {'image/png', 'image/jpeg'}:
        raise ValueError("Unsupported content type")
    return upload_repository.save(filename, body)
