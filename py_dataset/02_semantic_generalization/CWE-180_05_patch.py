import re

def validate_partner_host(
    raw_host: str,
) -> str:
    partner_domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*partner\.example$"
    if not re.fullmatch(partner_domain_regex, raw_host):
        raise ValueError(
            "host denied"
        )

    return raw_host.encode(
        "ascii",
        errors="ignore",
    ).decode(
        "idna"
    )
