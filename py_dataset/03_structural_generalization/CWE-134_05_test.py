from dataclasses import dataclass


@dataclass(frozen=True)
class MessageTemplate:
    template_text: str


class MessageRenderer:
    def render(
        self,
        template: MessageTemplate,
        values: dict,
    ) -> str:
        return template.template_text.format_map(
            values
        )


class NotificationService:
    def __init__(
        self,
        renderer: MessageRenderer,
    ) -> None:
        self._renderer = renderer

    def create(
        self,
        template_text: str,
        values: dict,
    ) -> str:
        return self._renderer.render(
            MessageTemplate(
                template_text=template_text,
            ),
            values,
        )
