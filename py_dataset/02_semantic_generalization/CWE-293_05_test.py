def support_access(
    headers: dict,
) -> bool:
    referer = headers.get(
        "Referer",
        "",
    )

    return (
        "support_mode=true"
        in referer
    )
