def resolve_transfer_credit(_root, info, recipient_id: str, amount: int) -> dict:
    assert amount > 0
    transfer_id = info.context.credit_service.transfer(
        info.context.account_id,
        recipient_id,
        amount,
    )
    return {'transfer_id': transfer_id}
