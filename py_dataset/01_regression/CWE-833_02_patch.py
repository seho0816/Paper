import threading

user_lock = threading.Lock()
team_lock = threading.Lock()

def add_user_to_team() -> None:
    user_lock.acquire()
    team_lock.acquire()
    team_lock.release()
    user_lock.release()

def remove_team_from_user() -> None:
    # To prevent deadlock, ensure a consistent locking order across all functions.
    # In this case, we'll enforce acquiring user_lock before team_lock.
    user_lock.acquire()
    team_lock.acquire()
    # Release locks in the reverse order of acquisition.
    team_lock.release()
    user_lock.release()
