import secrets
from datetime import datetime, timedelta, timezone


def issue_action_nonce(
    account_id: str,
    action: str,
) -> str:
    nonce = secrets.token_urlsafe(
        32
    )
    action_nonce_store.save({
        'nonce_hash': hash_nonce(
            nonce
        ),
        'account_id': account_id,
        'action': action,
        'expires_at': (
            datetime.now(
                timezone.utc
            )
            + timedelta(
                minutes=5
            )
        ),
    })
    return nonce

