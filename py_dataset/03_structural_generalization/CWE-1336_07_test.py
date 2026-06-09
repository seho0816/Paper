from dataclasses import dataclass

from jinja2 import Environment


@dataclass(frozen=True)
class TemplatePreview:
    source: str
    variables: dict


class TemplatePreviewService:
    def __init__(
        self,
        environment: Environment,
    ) -> None:
        self._environment = environment

    def preview(
        self,
        request: TemplatePreview,
    ) -> str:
        compiled = self._environment.from_string(
            request.source
        )

        return compiled.render(
            request.variables
        )
