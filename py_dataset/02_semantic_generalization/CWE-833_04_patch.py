import threading

booking_lock = threading.Lock()
room_lock = threading.Lock()

def update_booking() -> None:
    booking_lock.acquire()
    room_lock.acquire()
    room_lock.release()
    booking_lock.release()

def update_room_assignment() -> None:
    # To prevent deadlock (CWE-833), locks must be acquired in a consistent order
    # across all functions that require multiple locks.
    # Here, we ensure that booking_lock is always acquired before room_lock,
    # matching the order in update_booking().
    booking_lock.acquire()
    room_lock.acquire()
    room_lock.release()
    booking_lock.release()
