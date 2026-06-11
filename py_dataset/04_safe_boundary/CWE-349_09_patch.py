ALLOWED_PROFILE_FIELDS = {
    "display_name",
    "timezone",
    "locale",
}


def build_effective_context(
    server_claims: dict,
    request_json: dict,
) -> dict:
    profile_update = {
        key: request_json[
            key
        ]
        for key in ALLOWED_PROFILE_FIELDS
        if key in request_json
    }

    return {
        "auth": dict(
            server_claims
        ),
        "profile_update": profile_update,
    }

