def create_image_preview(
    image_body: bytes,
    session_id: str,
) -> bytes:
    preview = resize_and_optimize_image(
        image_body
    )
    session = session_repository.find(
        session_id
    )

    if session is None:
        raise PermissionError(
            "authentication required"
        )

    return preview
