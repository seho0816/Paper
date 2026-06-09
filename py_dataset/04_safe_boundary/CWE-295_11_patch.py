import httpx
import os


async def fetch_partner(
    url: str,
    ca_bundle: str,
) -> bytes:
    # CWE-295: Improper Certificate Validation
    # The 'verify' parameter in httpx can be vulnerable if it allows untrusted or
    # malicious certificate authority (CA) bundles, or if it can be set to disable validation.
    # The original code 'verify=ca_bundle' allows 'ca_bundle' to be an arbitrary string.
    # If 'ca_bundle' points to an attacker-controlled CA file, it enables MITM attacks.

    # To fix this, we ensure that certificate validation is always performed using trusted CAs.
    # We explicitly set 'verify_setting' to True (system CAs) as the secure default.
    # We then check the 'ca_bundle' argument:
    # - If 'ca_bundle' explicitly signals to use system CAs (e.g., "true", "1", "default"),
    #   or if it's an empty string or a non-existent path that would otherwise cause an error,
    #   we maintain the secure default of True.
    # - If 'ca_bundle' explicitly signals to disable validation (e.g., "false", "0"),
    #   we override it to True, as disabling validation is the core of CWE-295.
    # - If 'ca_bundle' is any other string (implying a custom CA bundle path),
    #   we must consider it potentially untrusted, as we cannot verify its trustworthiness.
    #   To prevent CWE-295, we therefore default to using system CAs.

    verify_setting = True  # Secure default: use system-wide trusted CAs

    if ca_bundle:
        # Check for explicit boolean-like strings
        if ca_bundle.lower() in ("true", "1", "default", "system"):
            verify_setting = True
        elif ca_bundle.lower() in ("false", "0"):
            # Explicitly disallow disabling verification, override to secure default.
            verify_setting = True
        else:
            # For any other non-empty string, it's presumed to be a path to a custom CA bundle.
            # To address CWE-295, an arbitrary path cannot be considered trusted without
            # additional out-of-scope validation (e.g., whitelisting, cryptographic checks).
            # Therefore, for security, we default to using system CAs instead of an arbitrary path.
            # If the custom CA bundle is critical, the application should ensure its trustworthiness
            # through other means (e.g., pre-configured trusted paths, bundled with the application).
            verify_setting = True
    # If ca_bundle is an empty string, the default verify_setting = True is maintained.

    async with httpx.AsyncClient(
        verify=verify_setting,  # Use the determined secure verification setting
        timeout=10.0,
    ) as client:
        response = await client.get(
            url,
        )
        response.raise_for_status()

        return response.content
