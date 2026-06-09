def allow_admin_action(
    headers: dict,
) -> bool:
    referer = headers.get(
        "Referer",
        "",
    )

    return referer.startswith(
        "https://admin.example.com/"
    )
