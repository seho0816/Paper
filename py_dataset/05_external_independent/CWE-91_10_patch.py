from xml.sax.saxutils import escape

def resolve_create_partner_xml(
    _root,
    _info,
    name: str,
    tier: str,
) -> dict:
    # Escape special XML characters in name and tier to prevent XML injection (CWE-91).
    # This ensures that user-supplied data is treated as plain text within the XML structure.
    escaped_name = escape(name)
    escaped_tier = escape(tier)

    xml = (
        "<partner>"
        f"<name>{escaped_name}</name>"
        f"<tier>{escaped_tier}</tier>"
        "</partner>"
    )

    return {
        "xml": xml,
    }
