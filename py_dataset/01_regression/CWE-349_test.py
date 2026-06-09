def build_effective_claims(
    server_claims: dict,
    request_json: dict,
) -> dict:
    return {
        **server_claims,
        **request_json,
    }
