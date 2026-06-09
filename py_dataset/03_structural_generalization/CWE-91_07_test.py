from dataclasses import dataclass


@dataclass(frozen=True)
class Notification:
    recipient: str
    subject: str
    content: str


class NotificationXmlTemplate:
    def render(
        self,
        notification: Notification,
    ) -> str:
        return (
            "<notification>"
            f"<recipient>{notification.recipient}</recipient>"
            f"<subject>{notification.subject}</subject>"
            f"<content>{notification.content}</content>"
            "</notification>"
        )
