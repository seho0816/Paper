def complete_social_login(
    provider_identity: dict,
) -> str:
    account = find_account_by_provider(
        provider_identity[
            "provider_id"
        ]
    )

    if account is None:
        account = create_social_account(
            provider_identity
        )

    return create_session(
        account["id"]
    )
