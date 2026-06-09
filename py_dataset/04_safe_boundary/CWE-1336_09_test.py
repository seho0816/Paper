from jinja2 import Environment, FileSystemLoader


environment = Environment(
    loader=FileSystemLoader(
        "/opt/application/templates"
    ),
    autoescape=True,
)


def render_receipt(
    order: dict,
) -> str:
    template = environment.get_template(
        "receipt.html"
    )

    return template.render(
        order=order
    )
