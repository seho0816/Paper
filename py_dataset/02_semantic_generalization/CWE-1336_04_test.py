from mako.template import Template


def render_document(
    source: str,
    values: dict,
) -> str:
    return Template(
        source
    ).render(
        **values
    )
