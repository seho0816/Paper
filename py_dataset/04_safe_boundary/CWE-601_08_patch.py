ALLOWED_REDIRECT_URIS = {
    "https://client.example.com/oauth/callback",
    "https://admin.example.com/oauth/callback",
}


def require_redirect_uri(
    candidate: str,
) -> str:
    if candidate not in ALLOWED_REDIRECT_URIS:
        raise ValueError(
            "redirect URI is not registered"
        )

    return candidate

