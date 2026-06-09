def resolve_external_profile_url(
    _root,
    _info,
    access_token: str,
) -> dict:
    return {
        "url": (
            "https://profile.example/api"
            "?access_token="
            + access_token
        ),
    }
