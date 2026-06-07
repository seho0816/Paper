users = {
    "mube": {
        "id": "user-100",
        "backup_codes": ["BACKUP-1", "BACKUP-2"],
        "mfa_enabled": True,
    }
}


class BackupLoginService:
    def login_with_backup_code(self, username: str, code: str) -> dict | None:
        user = users.get(username)

        if user is None:
            return None

        if code in user["backup_codes"]:
            # CWE-288 Fix: Invalidate the used backup code to prevent reuse.
            user["backup_codes"].remove(code)
            return create_session(user["id"])

        return None


def create_session(user_id: str) -> dict[str, str]:
    return {"user_id": user_id}
