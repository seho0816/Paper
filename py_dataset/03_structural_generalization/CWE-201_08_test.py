from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryNotification:
    account_id: str
    email: str
    recovery_secret: str


class RecoveryNotificationService:
    def send(self, notification: RecoveryNotification) -> None:
        external_notification_client.post({
            "account_id": notification.account_id,
            "email": notification.email,
            "recovery_secret": notification.recovery_secret,
        })
