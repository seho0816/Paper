import html
from dataclasses import dataclass


@dataclass(frozen=True)
class Notification:
    title: str
    message: str


class NotificationTemplate:
    def render(self, notification: Notification) -> str:
        # CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
        # HTML-escape the user-controlled input before embedding it into the HTML output.
        escaped_title = html.escape(notification.title)
        escaped_message = html.escape(notification.message)
        return (
            "<aside>"
            f"<strong>{escaped_title}</strong>"
            f"<p>{escaped_message}</p>"
            "</aside>"
        )


class NotificationService:
    def __init__(self, template: NotificationTemplate) -> None:
        self._template = template

    def create_browser_payload(self, payload: dict) -> dict:
        notification = Notification(
            title=str(payload["title"]),
            message=str(payload["message"]),
        )

        return {
            "html": self._template.render(notification),
        }
