import threading

warehouse_one = threading.Lock()
warehouse_two = threading.Lock()

# Placeholder for the stock movement logic
# In a real application, this function would contain the critical section code
def move_stock(source: str, destination: str) -> None:
    # Simulate stock movement
    # print(f"Moving stock from {source} to {destination}")
    pass

def move_one_to_two() -> None:
    with warehouse_one:
        with warehouse_two:
            move_stock('one', 'two')

def move_two_to_one() -> None:
    # To prevent deadlock (CWE-833), locks must always be acquired in a consistent order.
    # Here, we ensure that warehouse_one is always acquired before warehouse_two,
    # mirroring the order in move_one_to_two.
    with warehouse_one:
        with warehouse_two:
            move_stock('two', 'one')
