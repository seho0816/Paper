import xml.sax.saxutils

def build_partner_profile_xml(
    name: str,
    tier: str,
) -> str:
    escaped_name = xml.sax.saxutils.escape(name)
    escaped_tier = xml.sax.saxutils.escape(tier)
    return (
        "<partner>"
        f"<name>{escaped_name}</name>"
        f"<tier>{escaped_tier}</tier>"
        "</partner>"
    )
