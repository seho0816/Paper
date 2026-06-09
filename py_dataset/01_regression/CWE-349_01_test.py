def build_profile_update(
    authenticated_context: dict,
    payload: dict,
) -> dict:
    update = dict(
        authenticated_context
    )
    update.update(
        payload
    )

    return update
