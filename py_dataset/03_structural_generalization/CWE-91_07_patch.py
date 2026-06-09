from dataclasses import dataclass
from xml.sax.saxutils import escape


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
        escaped_recipient = escape(notification.recipient)
        escaped_subject = escape(notification.subject)
        escaped_content = escape(notification.content)
        return (
            "<notification>"
            f"<recipient>{escaped_recipient}</recipient>"
            f"<subject>{escaped_subject}</subject>"
            f"<content>{escaped_content}</content>"
            "</notification>"
        )
