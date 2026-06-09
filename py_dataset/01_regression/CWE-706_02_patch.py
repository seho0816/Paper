def settle_partner(partner_display_name: str, amount: int) -> str:
    partner = partner_repository.find_by_display_name(
        partner_display_name
    )
    if partner is None:
        return "Settlement failed: Partner not found."
    return settlement_gateway.send(
        partner['bank_account_id'],
        amount,
    )
