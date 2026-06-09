from string import Template


ALLOWED_KEYS = {
    "name",
    "order_id",
}


def render_message(
    template_text: str,
    values: dict,
) -> str:
    safe_values = {
        key: str(
            values.get(
                key,
                "",
            )
        )
        for key in ALLOWED_KEYS
    }

    return Template(
        template_text
    ).safe_substitute(
        safe_values
    )
