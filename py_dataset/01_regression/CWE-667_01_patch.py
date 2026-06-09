import threading

inventory_lock = threading.Lock()

def reserve_inventory(sku: str, quantity: int) -> bool:
    with inventory_lock:
        available = inventory_repository.available(sku)
        if available < quantity:
            return False
        inventory_repository.decrement(sku, quantity)
    return True
