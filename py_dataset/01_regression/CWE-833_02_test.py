import threading

user_lock = threading.Lock()
team_lock = threading.Lock()

def add_user_to_team() -> None:
    user_lock.acquire()
    team_lock.acquire()
    team_lock.release()
    user_lock.release()

def remove_team_from_user() -> None:
    team_lock.acquire()
    user_lock.acquire()
    user_lock.release()
    team_lock.release()
