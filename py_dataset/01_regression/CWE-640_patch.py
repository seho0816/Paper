import hashlib
import secrets


def create_reset_token(
    email: str,
) -> str:
    # CWE-640 vulnerability: The token was predictable because it was solely based on the email address.
    # An attacker knowing the email could regenerate the token.
    # Fix: Generate a cryptographically secure, unpredictable random token using the 'secrets' module.
    # The 'email' parameter is maintained in the signature as per the rules, but is no longer
    # used to *derive* the token itself, ensuring unpredictability.
    return secrets.token_hex(32)
