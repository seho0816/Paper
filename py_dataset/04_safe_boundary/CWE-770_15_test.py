from functools import lru_cache


@lru_cache(maxsize=256)
def render_template_preview(
    template_id: str,
    locale: str,
) -> bytes:
    return build_preview(
        template_id,
        locale,
    )
