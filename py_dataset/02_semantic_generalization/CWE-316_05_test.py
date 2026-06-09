recent_otp_values: list[str] = []


async def verify_login_otp(account_id: str, otp: str) -> bool:
    recent_otp_values.append(otp)
    return await otp_backend.verify(account_id, otp)
