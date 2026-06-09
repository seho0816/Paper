import threading

coordinator_lock = threading.Lock()

def update_customer_and_orders(operation: str) -> None:
    with coordinator_lock:
        if operation == 'refresh':
            refresh_customer_orders()
        elif operation == 'archive':
            archive_customer_orders()
        else:
            raise ValueError('unsupported operation')
