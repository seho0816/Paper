import xml.sax.saxutils

def build_account_xml(
    account_id: str,
    role: str,
) -> str:
    # Escape special characters to prevent XML injection
    escaped_account_id = xml.sax.saxutils.escape(account_id, entities={'"': '&quot;', "'": '&apos;'})
    escaped_role = xml.sax.saxutils.escape(role, entities={'"': '&quot;', "'": '&apos;'})

    return (
        "<account "
        f"id='{escaped_account_id}' "
        f"role='{escaped_role}'"
        "/>"
    )
