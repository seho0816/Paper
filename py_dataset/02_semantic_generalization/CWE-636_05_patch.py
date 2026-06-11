from some_mfa_library import ServiceUnavailable

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
        # CWE-636 fix: The original code returned True if the MFA service was unavailable,
        # which created a security bypass. If the MFA service cannot verify the code,
        # it should be treated as a verification failure, not a success.
        # Returning False ensures that authentication fails if MFA verification
        # cannot be performed due to service unavailability.
        return False
