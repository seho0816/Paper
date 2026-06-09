otp_store = {
    "user-100": "123456",
}


def verify_otp(
    user_id: str,
    code: str,
) -> bool:
    expected = otp_store.get(
        user_id
    )

    return (
        expected
        == code
    )
