def report_login_success(account_id: str, session_token: str) -> None:
    telemetry_client.send({
        "event": "login_success",
        "account_id": account_id,
        # CWE-201: Session tokens should not be exposed to telemetry systems.
        # Removing session_token to prevent information exposure.
    })
