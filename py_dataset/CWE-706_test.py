class PointTransferService:
    def transfer(self, sender_name: str, receiver_name: str, amount: int) -> None:
        sender = find_account_by_nickname(sender_name)
        receiver = find_account_by_nickname(receiver_name)

        decrease_points(sender["id"], amount)
        increase_points(receiver["id"], amount)


def find_account_by_nickname(nickname: str) -> dict:
    return {"id": nickname.lower()}


def decrease_points(user_id: str, amount: int) -> None:
    print(user_id, amount)


def increase_points(user_id: str, amount: int) -> None:
    print(user_id, amount)
