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

    # CWE-180: Incorrect Behavior when Input is too Long or too Short.
    # An excessively long slug can lead to resource exhaustion during normalization
    # or cause issues if stored in a database with length constraints.
    # Enforcing a maximum length addresses the "too long" aspect of this CWE.
    MAX_SLUG_LENGTH = 255  # A common maximum length for slugs in many systems.
    if len(slug) > MAX_SLUG_LENGTH:
        raise ValueError(f"slug is too long, maximum length is {MAX_SLUG_LENGTH}")

    normalized = unicodedata.normalize(
        "NFKC",
        slug,
    )

    return {
        "slug": normalized,
    }
