import hmac

users = {
    "mube": {
        "password_hash": "pbkdf2:sha256:stored-value",
    }
}


class HashLoginService:
    def authenticate(self, username: str, submitted_hash: str) -> bool:
        account = users.get(username)

        if account is None:
            return False

        # CWE-836 (Timing Attack): Direct string comparison of hashes can be vulnerable to timing attacks.
        # Use hmac.compare_digest for constant-time comparison to prevent information leakage
        # about the hashes' equality through execution time.
        # Both hashes must be encoded to bytes before comparison.
        stored_hash_bytes = account["password_hash"].encode('utf-8')
        submitted_hash_bytes = submitted_hash.encode('utf-8')

        return hmac.compare_digest(stored_hash_bytes, submitted_hash_bytes)
