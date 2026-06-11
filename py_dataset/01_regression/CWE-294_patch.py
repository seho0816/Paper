import hmac

otp_store = {
    "user-100": "123456",
}


def verify_otp(
    user_id: str,
    code: str,
) -> bool:
    # Retrieve the expected OTP. If user_id is not found, get() returns None.
    expected_otp_str = otp_store.get(user_id)

    # To prevent timing attacks (CWE-294) that could reveal if a user_id exists
    # or how many characters match, we must ensure the comparison
    # takes a constant time regardless of input or existence.
    # If no OTP is found for the user, we use a dummy string of the expected length
    # to maintain constant-time comparison and prevent user enumeration through timing differences.
    # Assuming OTPs are 6 digits based on the provided example.
    if expected_otp_str is None:
        expected_otp_str = "000000"  # Dummy value of same length as a valid OTP

    # Convert both strings to bytes using a consistent encoding (e.g., 'utf-8')
    # as hmac.compare_digest expects byte-like objects.
    expected_bytes = expected_otp_str.encode('utf-8')
    code_bytes = code.encode('utf-8')

    # Use hmac.compare_digest for constant-time comparison of secrets.
    # This function is designed to prevent timing attacks.
    return hmac.compare_digest(expected_bytes, code_bytes)
