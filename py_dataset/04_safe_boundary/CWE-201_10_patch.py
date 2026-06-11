def track_password_reset_request(user_id: str, email: str, reset_token: str) -> None:
    analytics_event = {
        "event": "password_reset_requested",
        "user_id": user_id,
        "email_domain": email.rsplit("@", 1)[-1],
    }
    send_to_analytics(analytics_event)

