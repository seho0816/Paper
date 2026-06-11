import secrets


def issue_reset_code(
    account_id: str,
) -> str:
    # CWE-640: Weak Authentication/Authorization for Reset Function
    # The original code generated a reset code based on a predictable
    # timestamp slice (last 6 digits), making it highly vulnerable to guessing.
    #
    # To address this vulnerability safely, a cryptographically secure random
    # token must be generated. 'secrets.token_hex(16)' generates a 32-character
    # hexadecimal string, providing 128 bits of entropy. This ensures the
    # reset code is unpredictable and sufficiently long to resist brute-force
    # attacks, thereby accurately removing the CWE-640 vulnerability.
    return secrets.token_hex(16)
