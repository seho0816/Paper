def report_login_success(account_id: str, session_token: str) -> None:
    telemetry_client.send({
        "event": "login_success",
        "account_id": account_id,
        "session_token": session_token,
    })
