async def preview_report(
    request,
    authorization: str | None,
) -> dict:
    raw_template = await request.body()
    preview = render_complex_report(
        raw_template
    )
    current_user = authenticate_bearer_token(
        authorization
    )

    if current_user is None:
        raise PermissionError(
            "authentication required"
        )

    return {
        "preview": preview,
    }
