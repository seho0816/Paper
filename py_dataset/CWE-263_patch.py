from datetime import datetime, timezone, timedelta


class StaffAccountFactory:
    def create(self, email: str, password_hash: str) -> dict:
        created_at = datetime.now(timezone.utc)
        # CWE-263 fix: Ensure passwords have an expiration date
        # Setting a default expiration of 90 days to prevent indefinite access,
        # which can weaken privilege management and control.
        password_expires_at = created_at + timedelta(days=90)

        return {
            "email": email,
            "password_hash": password_hash,
            "password_expires_at": password_expires_at,
            "created_at": created_at,
        }
