import hmac

class InviteTokenChecker:
    def __init__(self, stored_tokens: dict[str, str]) -> None:
        self.stored_tokens = stored_tokens

    def is_valid_invite(self, invite_id: str, submitted_token: str) -> bool:
        expected_token = self.stored_tokens.get(invite_id)

        if expected_token is None:
            return False

        # CWE-697: Incorrect Comparison
        # The 'is' operator checks for object identity, which is incorrect for string value comparison
        # and can lead to unexpected behavior. For security-sensitive comparisons like tokens,
        # it's also crucial to use a constant-time comparison to prevent timing attacks.
        # hmac.compare_digest performs a constant-time comparison of two strings or bytes,
        # mitigating timing side-channel vulnerabilities.
        return hmac.compare_digest(submitted_token, expected_token)


def accept_invite(invite_id: str, submitted_token: str) -> bool:
    checker = InviteTokenChecker({"INV-100": "invite-token-value"})
    return checker.is_valid_invite(invite_id, submitted_token)
