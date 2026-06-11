import re

def resolve_render_template(
    _root,
    _info,
    template_text: str,
    variables: dict,
) -> dict:
    
    def safe_format(template: str, context: dict) -> str:
        pattern = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

        def replace_match(match):
            key = match.group(1)
            return str(context.get(key, match.group(0)))

        return pattern.sub(replace_match, template)

    return {
        "rendered": (
            safe_format(template_text, variables)
        ),
    }
