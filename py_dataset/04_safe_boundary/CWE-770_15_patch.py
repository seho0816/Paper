from functools import lru_cache


@lru_cache(maxsize=256)
def render_template_preview(
    template_id: str,
    locale: str,
) -> bytes:
    MAX_ID_LENGTH = 255
    MAX_LOCALE_LENGTH = 10

    if len(template_id) > MAX_ID_LENGTH:
        raise ValueError(f"template_id exceeds maximum allowed length of {MAX_ID_LENGTH} characters.")
    if len(locale) > MAX_LOCALE_LENGTH:
        raise ValueError(f"locale exceeds maximum allowed length of {MAX_LOCALE_LENGTH} characters.")

    return build_preview(
        template_id,
        locale,
    )
