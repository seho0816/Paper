MAX_TEMPLATE_BYTES = 1_000_000


async def preview_report(
    request,
    authorization: str | None,
) -> dict:
    current_user = authenticate_bearer_token(
        authorization
    )

    if current_user is None:
        raise PermissionError(
            "authentication required"
        )

    raw_template = await request.body()

    if len(
        raw_template
    ) > MAX_TEMPLATE_BYTES:
        raise ValueError(
            "template is too large"
        )

    job_id = enqueue_report_preview(
        current_user["id"],
        raw_template,
    )

    return {
        "job_id": job_id,
    }
