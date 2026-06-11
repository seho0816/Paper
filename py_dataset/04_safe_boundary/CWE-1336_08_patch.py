from string import Template


ALLOWED_KEYS = {
    "name",
    "date",
}


def render_custom_message(
    message: str,
    context: dict,
) -> str:
    values = {
        key: str(
            context.get(
                key,
                "",
            )
        )
        for key in ALLOWED_KEYS
    }

    return Template(
        message
    ).safe_substitute(
        values
    )

