from dataclasses import dataclass


@dataclass
class RecoveryChallenge:
    token: str
    account_id: str
    expires_at: int
    consumed: bool = False


class RecoveryService:
    def reset(
        self,
        challenge: RecoveryChallenge,
        new_password: str,
        now: int,
    ) -> bool:
        if challenge.consumed:
            return False

        if challenge.expires_at < now:
            return False

        update_password(
            challenge.account_id,
            new_password,
        )

        return True
