class ResetTokenVerifier:
    def verify(self, submitted_token: str, stored_token: str) -> bool:
        # CWE-178: Improper Handling of Case Sensitivity
        # For security-sensitive tokens like reset tokens, case sensitivity should be preserved
        # to maintain the token's entropy and prevent potential bypasses.
        # The .casefold() calls are removed to enforce a case-sensitive comparison.
        return submitted_token == stored_token


def validate_reset_request(token: str) -> bool:
    verifier = ResetTokenVerifier()
    return verifier.verify(token, "AaBbCcDd1234")
