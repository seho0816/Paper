def assign_permission(
    account_id: str,
    permissions: tuple[str, ...],
    permission_index: int,
) -> None:
    permission = permissions[
        permission_index
    ]
    grant_permission(
        account_id,
        permission,
    )
