def request_sms_code(
    phone_number: str,
) -> tuple[dict, int]:
    account = find_by_phone(
        phone_number
    )

    # Only send SMS if the account exists.
    # To prevent observable discrepancies (CWE-204),
    # the response will be the same regardless of whether the account was found.
    if account is not None:
        send_sms_code(
            phone_number
        )

    # Always return a success-like response to prevent attackers from
    # enumerating registered phone numbers based on different error messages or status codes.
    return {
        "sent": True,
    }, 200
