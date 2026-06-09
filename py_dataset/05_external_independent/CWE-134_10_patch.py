import string

def prepare_template_source(
    submitted_source: str,
    metadata: dict,
) -> str:
    return string.Template(submitted_source).substitute(metadata)
