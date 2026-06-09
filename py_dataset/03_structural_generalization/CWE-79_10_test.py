from dataclasses import dataclass


@dataclass(frozen=True)
class Notification:
    title: str
    message: str


class NotificationTemplate:
    def render(self, notification: Notification) -> str:
        return (
            "<aside>"
            f"<strong>{notification.title}</strong>"
            f"<p>{notification.message}</p>"
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
