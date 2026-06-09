def create_image_preview(
    image_body: bytes,
    session_id: str,
) -> bytes:
    session = session_repository.find(
        session_id
    )

    if session is None:
        raise PermissionError(
            "authentication required"
        )

    preview = resize_and_optimize_image(
        image_body
    )

    return preview
