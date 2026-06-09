class PointTransferService:
    def transfer(self, sender_name: str, receiver_name: str, amount: int) -> None:
        sender = find_account_by_nickname(sender_name)
        receiver = find_account_by_nickname(receiver_name)

        # CWE-706: Reliance on Non-Authentic Source (Authoritative Source)
        # The original `find_account_by_nickname` would create an ID from any string,
        # treating any input as an "authentic" account ID. This allows an attacker
        # to specify an arbitrary sender name.
        # The fix ensures that the sender and receiver accounts are actually found
        # (i.e., are from an authentic source of known accounts) before proceeding.
        # If an account is not found, it signifies a reliance on a non-authentic
        # (non-existent or unverified) source, and the operation should be rejected.
        if sender is None:
            raise ValueError(f"Sender account '{sender_name}' not found or not authentic.")
        if receiver is None:
            raise ValueError(f"Receiver account '{receiver_name}' not found or not authentic.")

        decrease_points(sender["id"], amount)
        increase_points(receiver["id"], amount)


# Simulate an "authentic" list of user IDs/nicknames that exist in the system.
# In a real application, this would come from a secure database or user management system.
_AUTHENTIC_NICKNAMES = {"alice", "bob", "charlie", "david", "eve"}


def find_account_by_nickname(nickname: str) -> dict | None:
    # CWE-706 fix: Instead of simply lowercasing any input and creating an ID,
    # this function now checks if the nickname actually exists in a predefined
    # (simulated) set of authentic nicknames. If the nickname is not found,
    # it is considered a "non-authentic source" for an account and returns None.
    normalized_nickname = nickname.lower()
    if normalized_nickname in _AUTHENTIC_NICKNAMES:
        return {"id": normalized_nickname}
    return None


def decrease_points(user_id: str, amount: int) -> None:
    print(f"Decreasing {amount} points from {user_id}")


def increase_points(user_id: str, amount: int) -> None:
    print(f"Increasing {amount} points to {user_id}")
