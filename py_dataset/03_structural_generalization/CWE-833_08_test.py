import threading

profile_lock = threading.Lock()
permission_lock = threading.Lock()

class ProfileChangedHandler:
    def handle(self, event: dict) -> None:
        profile_lock.acquire()
        permission_lock.acquire()
        synchronize_permissions(event)
        permission_lock.release()
        profile_lock.release()

class PermissionChangedHandler:
    def handle(self, event: dict) -> None:
        permission_lock.acquire()
        profile_lock.acquire()
        synchronize_profile(event)
        profile_lock.release()
        permission_lock.release()
