def update_role(
    request,
) -> None:
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
