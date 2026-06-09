from tornado.template import Template


def render_banner(
    source: str,
    context: dict,
) -> bytes:
    template = Template(
        source
    )

    return template.generate(
        **context
    )
