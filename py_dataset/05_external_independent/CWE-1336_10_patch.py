from jinja2.sandbox import SandboxedEnvironment


def resolve_preview_template(
    _root,
    _info,
    source: str,
    variables: dict,
) -> dict:
    env = SandboxedEnvironment()
    template = env.from_string(source)
    rendered = template.render(variables)

    return {
        "rendered": rendered,
    }
