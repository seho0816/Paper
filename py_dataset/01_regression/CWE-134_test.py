def render_message(
    template: str,
    values: dict,
) -> str:
    return template % values
