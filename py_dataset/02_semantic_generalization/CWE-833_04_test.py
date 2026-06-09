import threading

booking_lock = threading.Lock()
room_lock = threading.Lock()

def update_booking() -> None:
    booking_lock.acquire()
    room_lock.acquire()
    room_lock.release()
    booking_lock.release()

def update_room_assignment() -> None:
    room_lock.acquire()
    booking_lock.acquire()
    booking_lock.release()
    room_lock.release()
