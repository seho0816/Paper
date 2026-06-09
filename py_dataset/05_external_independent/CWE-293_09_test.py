async def admin_route(
    scope: dict,
) -> dict:
    headers = dict(
        scope["headers"]
    )
    referer = headers.get(
        b"referer",
        b"",
    ).decode(
        "utf-8"
    )

    if not referer.startswith(
        "https://admin.example.com/"
    ):
        raise PermissionError(
            "access denied"
        )

    return export_all_accounts()
