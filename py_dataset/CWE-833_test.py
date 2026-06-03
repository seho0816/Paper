import threading


inventory_lock = threading.Lock()
payment_lock = threading.Lock()


def reserve_then_charge() -> None:
    inventory_lock.acquire()
    payment_lock.acquire()
    payment_lock.release()
    inventory_lock.release()


def refund_then_restore() -> None:
    payment_lock.acquire()
    inventory_lock.acquire()
    inventory_lock.release()
    payment_lock.release()
