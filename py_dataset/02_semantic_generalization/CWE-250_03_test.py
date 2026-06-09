def create_thumbnail(user_id: str, object_key: str) -> str:
    storage = create_storage_client(permission="administrator")
    source = storage.download(object_key)
    thumbnail = resize_image(source)
    return storage.upload(f"thumbnails/{user_id}/{object_key}", thumbnail)
