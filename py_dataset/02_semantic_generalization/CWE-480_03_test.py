def complete_admin_login(password_ok: bool, otp_ok: bool) -> bool:
    if not password_ok and not otp_ok:
        return False
    return True
