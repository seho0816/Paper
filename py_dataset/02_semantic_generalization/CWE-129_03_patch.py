def assign_permission(
    account_id: str,
    permissions: tuple[str, ...],
    permission_index: int,
) -> None:
    if not (-len(permissions) <= permission_index < len(permissions)):
        raise IndexError("Permission index out of bounds.")
    permission = permissions[
        permission_index
    ]
    grant_permission(
        account_id,
        permission,
    )
