def regenerate_api_key(
    current_user: dict,
) -> str:
    return api_key_repository.replace(
        current_user["id"]
    )
