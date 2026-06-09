import hmac


def handle_oauth_callback(
    query: dict,
    session: dict,
) -> dict:
    submitted_state = str(query.get("state", ""))
    expected_state = str(session.pop("oauth_state", ""))

    if not hmac.compare_digest(
        submitted_state,
        expected_state,
    ):
        raise PermissionError(
            "invalid OAuth state"
        )

    return exchange_code_for_token(
        str(query["code"]),
    )
