def delete_account_route(
    account_id: str,
) -> dict:
    account_repository.delete(
        account_id
    )

    return {
        "deleted": True,
    }
