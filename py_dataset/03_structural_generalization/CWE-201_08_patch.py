from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryNotification:
    account_id: str
    email: str
    recovery_secret: str


class RecoveryNotificationService:
    def send(self, notification: RecoveryNotification) -> None:
        # CWE-201: Information Exposure Through Sent Data
        # The 'recovery_secret' is sensitive information and should not be directly
        # sent to an external notification client. Removing it prevents exposure.
        external_notification_client.post({
            "account_id": notification.account_id,
            "email": notification.email,
        })
