def resolve_render_template(
    _root,
    _info,
    template_text: str,
    variables: dict,
) -> dict:
    return {
        "rendered": (
            template_text.format_map(
                variables
            )
        ),
    }
