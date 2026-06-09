import unicodedata


def resolve_create_slug(
    _root,
    _info,
    slug: str,
) -> dict:
    if "/" in slug:
        raise ValueError(
            "invalid slug"
        )

    normalized = unicodedata.normalize(
        "NFKC",
        slug,
    )

    return {
        "slug": normalized,
    }
