def handle_oauth_callback(query: dict) -> dict:
    authorization_code = query.get("code")
    token = exchange_code_for_token(
        authorization_code,
    )

    return {
        "access_token": token,
    }
