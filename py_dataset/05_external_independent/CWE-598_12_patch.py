def resolve_external_profile_url(
    _root,
    _info,
    access_token: str,
) -> dict:
    # CWE-598: Information Exposure Through Query Strings in GET Request
    # Sensitive information like access tokens should not be transmitted in URL query strings,
    # as they can be logged, exposed in referrer headers, or browser history.
    # The access_token has been removed from the URL.
    # The client consuming this URL should be responsible for passing the access_token securely,
    # typically via an Authorization header (e.g., "Authorization: Bearer <access_token>")
    # when making the actual HTTP request to the external profile API.
    return {
        "url": "https://profile.example/api",
    }
