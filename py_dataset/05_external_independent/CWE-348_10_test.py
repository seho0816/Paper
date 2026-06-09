def create_reset_url(
    request,
    token: str,
) -> str:
    return (
        "https://"
        + request.get_host()
        + "/account/reset/"
        + token
    )
