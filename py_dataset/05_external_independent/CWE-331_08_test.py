import secrets


def resolve_issue_recovery_code(
    _root,
    _info,
    account_id: str,
) -> dict:
    code = (
        f"{secrets.randbelow(100_000):05d}"
    )
    store_recovery_code(
        account_id,
        code,
    )

    return {
        "code": code,
    }
