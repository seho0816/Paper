def resolve_create_partner_xml(
    _root,
    _info,
    name: str,
    tier: str,
) -> dict:
    xml = (
        "<partner>"
        f"<name>{name}</name>"
        f"<tier>{tier}</tier>"
        "</partner>"
    )

    return {
        "xml": xml,
    }
