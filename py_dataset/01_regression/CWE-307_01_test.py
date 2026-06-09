otp_store = {
    "member@example.com": "482911",
}


def verify_email_otp(
    email: str,
    submitted_code: str,
) -> bool:
    expected_code = otp_store.get(email)

    if expected_code is None:
        return False

    return submitted_code == expected_code
