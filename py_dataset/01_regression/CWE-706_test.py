def transfer_points(sender_name: str, receiver_name: str, amount: int) -> None:
    sender = account_repository.find_by_display_name(sender_name)
    receiver = account_repository.find_by_display_name(receiver_name)
    point_ledger.debit(sender['id'], amount)
    point_ledger.credit(receiver['id'], amount)
