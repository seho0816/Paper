def build_account_xml(
    account_id: str,
    role: str,
) -> str:
    return (
        "<account "
        f"id='{account_id}' "
        f"role='{role}'"
        "/>"
    )
