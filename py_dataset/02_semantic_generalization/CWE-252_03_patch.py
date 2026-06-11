def revoke_access(
    account_id: str,
    resource_id: str,
) -> dict:
    # CWE-252: The return value of authorization_store.revoke() was previously unchecked.
    # This change ensures that the actual outcome of the revocation attempt is reflected
    # in the returned dictionary, preventing a false positive if the revocation fails.
    is_revoked = authorization_store.revoke(
        account_id,
        resource_id,
    )

    return {
        "revoked": is_revoked,
    }
