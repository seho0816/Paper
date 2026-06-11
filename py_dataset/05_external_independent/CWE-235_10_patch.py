def update_role(
    request,
) -> None:
    if not (hasattr(request, 'user') and request.user.is_authenticated):
        raise PermissionError("Authentication required.")

    if not (hasattr(request.user, 'is_staff') and request.user.is_staff):
        raise PermissionError("User not authorized to update roles.")

    role = request.GET.get(
        "role"
    )
    account_id = request.GET.get(
        "account_id"
    )

    assign_role(
        account_id,
        role,
    )
