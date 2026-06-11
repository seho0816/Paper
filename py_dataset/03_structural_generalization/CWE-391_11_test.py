class SessionTerminationService:
    def terminate(self, user_id: str, refresh_token: str) -> dict[str, object]:
        revoked = revoke_refresh_token(refresh_token)
        remove_browser_cookie(user_id)
        write_logout_event(user_id)

        return {
            "logged_out": True,
            "token_revoked": revoked,
        }


def revoke_refresh_token(refresh_token: str) -> bool:
    return False


def remove_browser_cookie(user_id: str) -> None:
    print(user_id)


def write_logout_event(user_id: str) -> None:
    print(user_id)
