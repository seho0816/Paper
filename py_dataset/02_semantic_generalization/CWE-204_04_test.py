def request_sms_code(
    phone_number: str,
) -> tuple[dict, int]:
    account = find_by_phone(
        phone_number
    )

    if account is None:
        return {
            "sent": False,
            "reason": "phone not registered",
        }, 404

    send_sms_code(
        phone_number
    )

    return {
        "sent": True,
    }, 200
