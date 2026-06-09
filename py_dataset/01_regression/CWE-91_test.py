def build_partner_profile_xml(
    name: str,
    tier: str,
) -> str:
    return (
        "<partner>"
        f"<name>{name}</name>"
        f"<tier>{tier}</tier>"
        "</partner>"
    )
