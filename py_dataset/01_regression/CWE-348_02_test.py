def callback_url(
    request: dict,
    state: str,
) -> str:
    scheme = request.get(
        "scheme",
        "https",
    )
    host = request[
        "headers"
    ].get(
        "Host"
    )

    return (
        f"{scheme}://{host}/oauth/callback"
        f"?state={state}"
    )
