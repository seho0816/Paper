def grant_trial_credit(
    account_id: str,
    campaign: dict,
) -> None:
    wallet_repository.add_credit(
        account_id,
        campaign[
            "credit_amount"
        ],
    )
