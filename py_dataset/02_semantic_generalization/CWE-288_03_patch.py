import os

def complete_social_login(
    provider_identity: dict,
) -> str:
    # CWE-288 Fix: Implement an internal verification step to prevent authentication bypass.
    # This assumes that 'provider_identity' should contain a proof of authenticity
    # (e.g., a shared secret or token) which is inserted by a trusted upstream process
    # after successfully verifying the social login with the external provider.
    # An attacker who crafts a 'provider_identity' dictionary without this secret
    # or with an incorrect one will be prevented from bypassing authentication.

    # Retrieve the expected secret key from environment variables.
    # Using [] access will raise KeyError if the environment variable is not set,
    # ensuring that this critical security configuration is mandatory.
    try:
        expected_verification_secret = os.environ["SOCIAL_LOGIN_SECRET_KEY"]
    except KeyError:
        raise RuntimeError(
            "CRITICAL: SOCIAL_LOGIN_SECRET_KEY environment variable is not set. "
            "Secure social login cannot be performed without this configuration."
        )

    # Validate that the 'provider_identity' contains the correct verification secret.
    # This acts as an internal authentication gate, ensuring the identity data
    # originated from a trusted, pre-verified source.
    if provider_identity.get("verification_secret") != expected_verification_secret:
        raise PermissionError(
            "Authentication bypass attempt detected: Invalid or missing "
            "social identity verification proof."
        )

    account = find_account_by_provider(
        provider_identity[
            "provider_id"
        ]
    )

    if account is None:
        account = create_social_account(
            provider_identity
        )

    return create_session(
        account["id"]
    )
