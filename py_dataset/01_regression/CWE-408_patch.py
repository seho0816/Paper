async def preview_report(
    request,
    authorization: str | None,
) -> dict:
    raw_template = await request.body()

    # CWE-408 fix: Ensure the report template body is not empty
    if not raw_template:
        raise ValueError("Report template body cannot be empty.")

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
