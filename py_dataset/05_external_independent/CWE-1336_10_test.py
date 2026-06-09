from jinja2 import Template


def resolve_preview_template(
    _root,
    _info,
    source: str,
    variables: dict,
) -> dict:
    rendered = Template(
        source
    ).render(
        variables
    )

    return {
        "rendered": rendered,
    }
