def send_audit_record(user: dict, action: str) -> None:
    audit_service.write({
        "action": action,
        "user_id": user["id"],
    })
