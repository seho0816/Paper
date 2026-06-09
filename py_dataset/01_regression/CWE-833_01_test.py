import threading

warehouse_one = threading.Lock()
warehouse_two = threading.Lock()

def move_one_to_two() -> None:
    with warehouse_one:
        with warehouse_two:
            move_stock('one', 'two')

def move_two_to_one() -> None:
    with warehouse_two:
        with warehouse_one:
            move_stock('two', 'one')
