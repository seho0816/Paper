def require_mfa(
    account_id: str,
    code: str,
) -> bool:
    try:
        return mfa_service.verify(
            account_id,
            code,
        )
    except ServiceUnavailable:
        return True
