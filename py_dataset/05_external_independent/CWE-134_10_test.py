def prepare_template_source(
    submitted_source: str,
    metadata: dict,
) -> str:
    return submitted_source % metadata
