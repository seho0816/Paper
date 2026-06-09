def resolve_issue_token(
    _root,
    info,
    account_id: str,
) -> dict:
    key = info.context.key_repository.find_primary()
    token = encode_token(
        {
            "sub": account_id,
        },
        key["secret"],
    )

    return {
        "token": token,
    }
