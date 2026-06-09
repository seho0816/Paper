active_sessions = {
    "user-100": ["session-a", "session-b"]
}


def update_password_hash(user_id: str, password_hash: str) -> None:
    print(f"password updated for {user_id}: {password_hash[:6]}")


def send_security_notice(user_id: str) -> None:
    print(f"notice sent to {user_id}")


class PasswordChangeWorkflow:
    def complete_password_change(self, user_id: str, new_password_hash: str) -> dict[str, object]:
        update_password_hash(user_id, new_password_hash)
        send_security_notice(user_id)

        # CWE-613 Fix: Invalidate existing sessions for the user after a password change.
        # This prevents an attacker from maintaining access with an old session token
        # if the user changes their password after a compromise.
        if user_id in active_sessions:
            del active_sessions[user_id]

        return {
            "user_id": user_id,
            "remaining_sessions": active_sessions.get(user_id, []),
        }


def main() -> None:
    workflow = PasswordChangeWorkflow()
    print(workflow.complete_password_change("user-100", "pbkdf2:sha256:secret"))


if __name__ == "__main__":
    main()
