from jinja2 import Template


def render_custom_message(
    template_source: str,
    context: dict,
) -> str:
    template = Template(
        template_source
    )

    return template.render(
        context
    )
