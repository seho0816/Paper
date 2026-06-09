def normalize_email(
    email: str,
) -> str:
    local_part, domain = email.strip().split(
        "@",
        1,
    )

    return (
        local_part
        + "@"
        + domain.casefold()
    )
