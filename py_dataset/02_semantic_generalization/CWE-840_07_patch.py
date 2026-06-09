def grant_trial_credit(
    account_id: str,
    campaign: dict,
) -> None:
    # CWE-840 Business Logic Error: Prevent granting the same trial credit multiple times.
    # Assumes 'campaign' dictionary contains a unique identifier 'id' for the campaign
    # and that wallet_repository provides a method to check if the credit has already been granted.
    if wallet_repository.has_granted_campaign_credit(account_id, campaign["id"]):
        return

    wallet_repository.add_credit(
        account_id,
        campaign[
            "credit_amount"
        ],
    )
