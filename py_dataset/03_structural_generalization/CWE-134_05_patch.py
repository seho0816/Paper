from dataclasses import dataclass
from string import Template


@dataclass(frozen=True)
class MessageTemplate:
    template_text: str


class MessageRenderer:
    def render(
        self,
        template: MessageTemplate,
        values: dict,
    ) -> str:
        # CWE-134: Uncontrolled Format String vulnerability.
        # Using str.format_map directly with untrusted `template_text` allows an attacker
        # to control the format string, potentially leading to information disclosure
        # or unexpected behavior.
        #
        # Mitigation: Use `string.Template` which provides a simpler and safer
        # templating mechanism. It restricts placeholders to simple named fields
        # (e.g., $variable or ${variable}) and does not allow arbitrary attribute
        # access, item access, or general Python expressions within the template string,
        # thereby preventing format string attacks.
        #
        # Note: This changes the expected template placeholder syntax from `{key}` to `$key`
        # or `${key}`. This is a necessary consequence of switching to a safer templating
        # mechanism that directly addresses the CWE-134 vulnerability by limiting the
        # capabilities of the user-controlled template string.
        return Template(template.template_text).substitute(values)


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
