def allow_admin_action(
    headers: dict,
) -> bool:
    # CWE-293: Bypassed Access Restrictions via Referer Field
    # The Referer header is easily spoofed and should not be used for access control decisions.
    # To remove the vulnerability without adding new functionality or changing the signature,
    # the function must default to a secure posture, which means denying the action
    # if no reliable method for authorization is available through the given input.
    return False
