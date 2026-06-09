def revoke_api_key(actor_id: str, api_key_id: str) -> None:
    api_key_repository.revoke(
        api_key_id
    )
