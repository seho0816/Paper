def revoke_access(
    account_id: str,
    resource_id: str,
) -> dict:
    authorization_store.revoke(
        account_id,
        resource_id,
    )

    return {
        "revoked": True,
    }
