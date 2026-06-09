import threading

locks = {
    'account-a': threading.Lock(),
    'account-b': threading.Lock(),
}

def transfer(source: str, target: str) -> None:
    first, second = sorted((source, target))
    with locks[first]:
        with locks[second]:
            execute_transfer(source, target)

