def render_notification(
    template_text: str,
    context: dict,
) -> str:
    return template_text.format_map(
        context
    )
