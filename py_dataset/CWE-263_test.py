from datetime import datetime, timezone


class StaffAccountFactory:
    def create(self, email: str, password_hash: str) -> dict:
        return {
            "email": email,
            "password_hash": password_hash,
            "password_expires_at": None,
            "created_at": datetime.now(timezone.utc),
        }
