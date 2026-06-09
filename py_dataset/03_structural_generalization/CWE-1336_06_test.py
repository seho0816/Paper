from dataclasses import dataclass

from jinja2 import Template


@dataclass(frozen=True)
class StoredTemplate:
    source: str


class TemplateRepository:
    def load(
        self,
        template_id: str,
    ) -> StoredTemplate:
        return StoredTemplate(
            source=database.load_template(
                template_id
            )
        )


class MessageRenderer:
    def __init__(
        self,
        repository: TemplateRepository,
    ) -> None:
        self._repository = repository

    def render(
        self,
        template_id: str,
        values: dict,
    ) -> str:
        stored = self._repository.load(
            template_id
        )

        return Template(
            stored.source
        ).render(
            values
        )
