import secrets
import string

def create_sms_recovery_code(
    phone_number: str,
) -> str:
    # CWE-640: The original code used the last 6 digits of the phone number,
    # making the recovery code predictable and easily guessable if the phone number is known.
    # To fix this, a cryptographically strong, random 6-digit code is generated.
    code_length = 6
    recovery_code = ''.join(secrets.choice(string.digits) for _ in range(code_length))

    return recovery_code
