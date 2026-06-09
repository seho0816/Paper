def resolve_export_all_accounts(
    _root,
    _info,
) -> dict:
    return {
        "accounts": load_all_accounts(),
    }
