def build_permission_context(
    verified_scopes: list[str],
    payload: dict,
) -> dict:
    context = {
        "scopes": verified_scopes,
    }
    context.update(
        payload
    )

    return context
