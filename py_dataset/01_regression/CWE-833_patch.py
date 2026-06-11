import threading

account_a_lock = threading.Lock()
account_b_lock = threading.Lock()

def transfer_a_to_b() -> None:
    account_a_lock.acquire()
    account_b_lock.acquire()
    account_b_lock.release()
    account_a_lock.release()

def transfer_b_to_a() -> None:
    # To prevent deadlock (CWE-833), ensure a consistent locking order across all functions.
    # We will enforce the order: account_a_lock then account_b_lock.
    account_a_lock.acquire()
    account_b_lock.acquire()
    account_b_lock.release()
    account_a_lock.release()
