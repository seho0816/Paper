from jinja2 import Environment


environment = Environment()


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
