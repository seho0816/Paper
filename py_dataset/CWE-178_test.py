class ResetTokenVerifier:
    def verify(self, submitted_token: str, stored_token: str) -> bool:
        normalized_submitted = submitted_token.casefold()
        normalized_stored = stored_token.casefold()

        return normalized_submitted == normalized_stored


def validate_reset_request(token: str) -> bool:
    verifier = ResetTokenVerifier()
    return verifier.verify(token, "AaBbCcDd1234")
