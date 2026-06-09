from jinja2 import Template


def send_saved_template(
    template_id: str,
    context: dict,
) -> None:
    source = template_repository.load_source(
        template_id
    )
    body = Template(
        source
    ).render(
        context
    )
    send_email_body(
        body
    )
