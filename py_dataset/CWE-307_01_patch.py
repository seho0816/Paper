otp_records = {
    "01012345678": {
        "code": "482911",
        "expires_at": 9999999999,
        "failed_attempts": 0,  # Initialize failed attempts counter for CWE-307
    }
}

MAX_FAILED_ATTEMPTS = 3  # Define the maximum allowed failed attempts for CWE-307


class SmsOtpVerifier:
    def verify(self, phone_number: str, submitted_code: str) -> bool:
        record = otp_records.get(phone_number)

        if record is None:
            return False

        # CWE-307: Prevent brute-force attacks by limiting failed attempts
        # Safely retrieve 'failed_attempts', defaulting to 0 if not present
        current_failed_attempts = record.get("failed_attempts", 0)

        if current_failed_attempts >= MAX_FAILED_ATTEMPTS:
            return False  # Too many failed attempts, verification is blocked

        if record["code"] == submitted_code:
            # OTP successfully verified.
            # In a production system, this OTP record would typically be
            # removed or marked as used after successful verification
            # to prevent reuse.
            return True
        else:
            # Increment failed attempts counter on incorrect code submission
            record["failed_attempts"] = current_failed_attempts + 1
            return False


def complete_phone_verification(payload: dict[str, str]) -> bool:
    verifier = SmsOtpVerifier()
    return verifier.verify(payload["phone"], payload["code"])
