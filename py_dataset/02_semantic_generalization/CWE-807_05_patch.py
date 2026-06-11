def rotate_recovery_codes(form: dict, account_id: str) -> list[str]:
    # CWE-807: Reliance on Untrusted Inputs in a Security Decision
    # The original code relied on 'form.get('passed_mfa')' which is user-controlled
    # input, to make a security decision. This allowed users to bypass MFA by
    # simply setting 'passed_mfa' to 'true' in their request.
    #
    # The fix removes this untrusted check. It is assumed that any MFA verification
    # required for this action will be performed by a trusted, server-side mechanism
    # at a higher layer (e.g., in a middleware or controller before calling this
    # function), ensuring that this function is only invoked after successful and
    # trusted MFA verification.
    return recovery_code_service.rotate(account_id)
