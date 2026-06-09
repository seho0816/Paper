import bleach

ALLOWED_TAGS = {
    "p",
    "strong",
    "em",
    "ul",
    "li",
}


def render_user_article(raw_html: str) -> str:
    return bleach.clean(
        raw_html,
        tags=ALLOWED_TAGS,
        attributes={},
        protocols={"https"},
        strip=True,
    )
