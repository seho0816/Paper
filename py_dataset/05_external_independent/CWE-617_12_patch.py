def resolve_transfer_credit(_root, info, recipient_id: str, amount: int) -> dict:
    if amount <= 0:
        raise ValueError("Transfer amount must be positive.")
    transfer_id = info.context.credit_service.transfer(
        info.context.account_id,
        recipient_id,
        amount,
    )
    return {'transfer_id': transfer_id}
