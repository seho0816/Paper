import threading

account_a_lock = threading.Lock()
account_b_lock = threading.Lock()

def transfer_a_to_b() -> None:
    account_a_lock.acquire()
    account_b_lock.acquire()
    account_b_lock.release()
    account_a_lock.release()

def transfer_b_to_a() -> None:
    account_b_lock.acquire()
    account_a_lock.acquire()
    account_a_lock.release()
    account_b_lock.release()
