import threading

# A lock to protect the shared 'reward_points' resource from race conditions.
# CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization.
# The lock ensures that only one thread can modify or read the 'reward_points'
# at a time during the critical section within 'spend_points'.
reward_points_lock = threading.Lock()

reward_points = {
    "member-1": 1000,
}


def spend_points(
    member_id: str,
    amount: int,
) -> bool:
    # Acquire the lock before accessing the shared 'reward_points' dictionary.
    # The 'with' statement ensures the lock is released automatically even if errors occur.
    with reward_points_lock:
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
