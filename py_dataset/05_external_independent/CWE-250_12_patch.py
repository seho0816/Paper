def resolve_my_orders(_root, info, year: int) -> list[dict]:
    # CWE-250: Execution with Unnecessary Privileges.
    # The original code used an "administrator" role to fetch a user's own orders,
    # which is an unnecessary privilege.
    # The fix is to create an SDK with the current user's privileges (or a more restricted role),
    # ensuring the principle of least privilege is followed.
    # Assuming create_sdk() without a role argument defaults to the current user's context/privileges.
    user_sdk = info.context.create_sdk()
    return user_sdk.orders.search(
        user_id=info.context.user["id"],
        year=year,
    )
