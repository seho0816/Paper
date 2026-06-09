from string import Template

def render_notification(
    template_text: str,
    context: dict,
) -> str:
    return Template(template_text).substitute(
        context
    )
