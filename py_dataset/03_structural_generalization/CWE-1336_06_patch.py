from dataclasses import dataclass
from jinja2.sandbox import SandboxedEnvironment


@dataclass(frozen=True)
class StoredTemplate:
    source: str


class TemplateRepository:
    def load(
        self,
        template_id: str,
    ) -> StoredTemplate:
        # 'database' is an assumed external dependency not defined in the provided snippet.
        # Its implementation is outside the scope of this CWE-1336 fix.
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

        # CWE-1336 fix: Use jinja2.sandbox.SandboxedEnvironment to prevent Server-Side Template Injection (SSTI).
        # This restricts potentially untrusted template code from accessing dangerous attributes or functions.
        env = SandboxedEnvironment()
        template = env.from_string(stored.source)

        return template.render(
            values
        )
