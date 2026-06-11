from string import Template

def localize_message(
    submitted_template: str,
    variables: dict,
) -> str:
    translated = translate(
        submitted_template
    )

    return Template(translated).safe_substitute(
        variables
    )
