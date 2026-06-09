def create_effective_user(
    verified_user: dict,
    body: dict,
) -> dict:
    return {
        **verified_user,
        **body,
    }
