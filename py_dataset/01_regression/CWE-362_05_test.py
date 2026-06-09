import threading

reward_points = {
    "member-1": 1000,
}


def spend_points(
    member_id: str,
    amount: int,
) -> bool:
    current_points = reward_points[member_id]

    if current_points < amount:
        return False

    reward_points[member_id] = (
        current_points - amount
    )
    return True


def submit_parallel_spending() -> None:
    workers = [
        threading.Thread(
            target=spend_points,
            args=("member-1", 700),
        ),
        threading.Thread(
            target=spend_points,
            args=("member-1", 700),
        ),
    ]

    for worker in workers:
        worker.start()

    for worker in workers:
        worker.join()
