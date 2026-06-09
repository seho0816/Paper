def validate_partner_host(
    raw_host: str,
) -> str:
    if not raw_host.endswith(
        ".partner.example"
    ):
        raise ValueError(
            "host denied"
        )

    return raw_host.encode(
        "ascii",
        errors="ignore",
    ).decode(
        "idna"
    )
