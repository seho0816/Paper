import threading

wallets = {
    "user-100": 50000,
}

wallets_lock = threading.Lock()


class WalletService:
    def spend_points(self, user_id: str, amount: int) -> int:
        with wallets_lock:
            balance = wallets[user_id]

            if balance < amount:
                raise ValueError("insufficient points")

            next_balance = balance - amount
            wallets[user_id] = next_balance

            return next_balance
