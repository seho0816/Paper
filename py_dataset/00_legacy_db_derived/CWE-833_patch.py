import threading


inventory_lock = threading.Lock()
payment_lock = threading.Lock()


def reserve_then_charge() -> None:
    inventory_lock.acquire()
    payment_lock.acquire()
    payment_lock.release()
    inventory_lock.release()


def refund_then_restore() -> None:
    # Changed lock acquisition order to be consistent with reserve_then_charge
    # to prevent deadlock (CWE-833). All functions requiring multiple locks
    # must acquire them in the same predefined order.
    inventory_lock.acquire()
    payment_lock.acquire()
    # Release order should be the reverse of the acquisition order.
    payment_lock.release()
    inventory_lock.release()
