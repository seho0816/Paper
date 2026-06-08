otp_codes = {
    "login:user-100": "771204",
}


class OtpVerifier:
    def verify_login_code(self, user_id: str, submitted_code: str) -> bool:
        key = f"login:{user_id}"
        expected_code = otp_codes.get(key)

        if expected_code is None or expected_code != submitted_code:
            return False

        # CWE-294 fix: Invalidate the OTP after successful verification to prevent reuse.
        # This addresses authentication bypass by ensuring OTPs are single-use.
        del otp_codes[key]

        return True


def complete_second_factor(user_id: str, code: str) -> dict[str, bool]:
    verifier = OtpVerifier()
    return {
        "verified": verifier.verify_login_code(user_id, code),
    }
