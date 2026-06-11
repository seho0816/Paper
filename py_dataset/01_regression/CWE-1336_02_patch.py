from jinja2 import Environment, SandboxedEnvironment


environment = SandboxedEnvironment(
    autoescape=True
)


def render_notice(
    submitted_source: str,
    values: dict,
) -> str:
    template = environment.from_string(
        submitted_source
    )

    return template.render(
        values
    )
