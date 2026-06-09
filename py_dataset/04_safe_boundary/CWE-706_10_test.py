def transfer_points(sender_id: str, receiver_id: str, amount: int) -> None:
    sender = account_repository.find_by_id(sender_id)
    receiver = account_repository.find_by_id(receiver_id)

    if sender is None or receiver is None:
        raise ValueError('invalid account identifier')

    point_ledger.debit(sender['id'], amount)
    point_ledger.credit(receiver['id'], amount)
