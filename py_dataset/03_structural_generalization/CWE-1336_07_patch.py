from dataclasses import dataclass

from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment


@dataclass(frozen=True)
class TemplatePreview:
    source: str
    variables: dict


class TemplatePreviewService:
    def __init__(
        self,
        environment: Environment,
    ) -> None:
        # CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine
        # To prevent Server-Side Template Injection (SSTI) when rendering user-provided
        # template 'source', ensure that the Jinja2 environment used is sandboxed.
        # If the provided 'environment' is not already a SandboxedEnvironment,
        # create a new SandboxedEnvironment instance from it, inheriting its configuration
        # but enforcing sandboxing rules.
        if not isinstance(environment, SandboxedEnvironment):
            self._environment = SandboxedEnvironment.from_env(environment)
        else:
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
