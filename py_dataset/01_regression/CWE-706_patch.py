import account_repository
import point_ledger

def transfer_points(sender_name: str, receiver_name: str, amount: int) -> None:
    sender = account_repository.find_by_display_name(sender_name)
    if not sender or sender['display_name'] != sender_name:
        raise ValueError(f"Sender account '{sender_name}' not found or display name mismatch.")

    receiver = account_repository.find_by_display_name(receiver_name)
    if not receiver or receiver['display_name'] != receiver_name:
        raise ValueError(f"Receiver account '{receiver_name}' not found or display name mismatch.")

    point_ledger.debit(sender['id'], amount)
    point_ledger.credit(receiver['id'], amount)
