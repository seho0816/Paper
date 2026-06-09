def send_audit_record(user: dict, action: str) -> None:
    audit_service.write({
        "action": action,
        "user_id": user["id"],
        "national_id": user["national_id"],
        "email": user["email"],
    })
