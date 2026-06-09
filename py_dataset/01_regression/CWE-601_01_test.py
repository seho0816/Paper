def finish_login(
    query: dict,
) -> tuple[int, dict[str, str], str]:
    next_url = query.get(
        "redirect_uri",
        "/",
    )

    return (
        302,
        {
            "Location": next_url,
        },
        "",
    )
