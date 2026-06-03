import threading


attempt_lock = threading.Lock()
attempts: list[str] = []


class LoginAttemptRecorder:
    def record(self, user_id: str, blocked: bool) -> bool:
        attempt_lock.acquire()

        if blocked:
            return False

        attempts.append(user_id)
        attempt_lock.release()
        return True


def main() -> None:
    recorder = LoginAttemptRecorder()
    print(recorder.record("user-100", True))


if __name__ == "__main__":
    main()
