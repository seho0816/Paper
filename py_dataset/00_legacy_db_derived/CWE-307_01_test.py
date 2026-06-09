otp_records = {
    "01012345678": {
        "code": "482911",
        "expires_at": 9999999999,
    }
}


class SmsOtpVerifier:
    def verify(self, phone_number: str, submitted_code: str) -> bool:
        record = otp_records.get(phone_number)

        if record is None:
            return False

        return record["code"] == submitted_code


def complete_phone_verification(payload: dict[str, str]) -> bool:
    verifier = SmsOtpVerifier()
    return verifier.verify(payload["phone"], payload["code"])
