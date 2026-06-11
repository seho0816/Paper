def complete_step_up(account_id: str, otp: str) -> str:
    status = otp_provider.check(account_id, otp)
    if not status:
        raise PermissionError('OTP verification failed')
    return session_service.elevate(account_id)
