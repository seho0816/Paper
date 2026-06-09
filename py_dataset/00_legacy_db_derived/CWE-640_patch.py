import secrets
import time


reset_tokens: dict[str, dict] = {
    "RESET-100": {
        "valid": True,
    }
}

# CWE-640 Fix: Token expiry and single-use enforcement
_TOKEN_TTL_SECONDS = 900  # 15 minutes


def generate_reset_token() -> str:
    """Generate a cryptographically secure, single-use reset token."""
    token = secrets.token_urlsafe(32)
    reset_tokens[token] = {
        "valid":      True,
        "created_at": time.time(),
    }
    return token


class PasswordResetService:
    def reset_password(self, token: str, user_id: str, new_hash: str) -> bool:
        token_record = reset_tokens.get(token)

        if token_record is None or not token_record["valid"]:
            return False

        # CWE-640 Fix: Reject expired tokens
        age = time.time() - token_record.get("created_at", 0)
        if age > _TOKEN_TTL_SECONDS:
            token_record["valid"] = False
            return False

        # CWE-640 Fix: Invalidate token immediately after use (single-use)
        token_record["valid"] = False

        update_password_hash(user_id, new_hash)
        return True


def update_password_hash(user_id: str, new_hash: str) -> None:
    print(user_id, new_hash)