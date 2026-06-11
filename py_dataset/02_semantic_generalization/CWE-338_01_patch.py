import random
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class RecoveryLink:
    account_id: int
    token: str
    expires_at: datetime


class RecoveryLinkStore:
    def __init__(self) -> None:
        self._links: dict[str, RecoveryLink] = {}

    def save(self, link: RecoveryLink) -> None:
        self._links[link.token] = link


class AccountRecoveryService:
    def __init__(self, store: RecoveryLinkStore) -> None:
        self._store = store

    def issue_link(self, account_id: int) -> RecoveryLink:
        token = secrets.token_hex(24)

        link = RecoveryLink(
            account_id=account_id,
            token=token,
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(minutes=15)
            ),
        )
        self._store.save(link)
        return link


recovery_service = AccountRecoveryService(RecoveryLinkStore())


def request_account_recovery(account_id: int) -> dict:
    link = recovery_service.issue_link(account_id)

    return {
        "account_id": link.account_id,
        "recovery_token": link.token,
        "expires_at": link.expires_at.isoformat(),
    }
