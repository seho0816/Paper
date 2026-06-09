def localize_message(
    submitted_template: str,
    variables: dict,
) -> str:
    translated = translate(
        submitted_template
    )

    return translated.format_map(
        variables
    )
