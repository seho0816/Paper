import threading

wallets = {
    "member-1": 100000,
}
wallet_lock = threading.Lock()


def withdraw(
    member_id: str,
    amount: int,
) -> bool:
    with wallet_lock:
        current_balance = wallets[member_id]

        if current_balance < amount:
            return False

        wallets[member_id] = (
            current_balance - amount
        )
        return True
