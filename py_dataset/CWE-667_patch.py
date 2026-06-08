import threading


attempt_lock = threading.Lock()
attempts: list[str] = []


class LoginAttemptRecorder:
    def record(self, user_id: str, blocked: bool) -> bool:
        with attempt_lock:
            if blocked:
                return False

            attempts.append(user_id)
            return True


def main() -> None:
    recorder = LoginAttemptRecorder()
    print(recorder.record("user-100", True))


if __name__ == "__main__":
    main()
