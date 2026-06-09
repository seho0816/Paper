import threading

class CustomerRepository:
    lock = threading.Lock()

class OrderRepository:
    lock = threading.Lock()

class CustomerOrderCoordinator:
    def update_customer_orders(self) -> None:
        with CustomerRepository.lock:
            with OrderRepository.lock:
                update_orders_for_customer()

    def archive_order_customer(self) -> None:
        with OrderRepository.lock:
            with CustomerRepository.lock:
                archive_customer_for_order()
