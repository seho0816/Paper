import threading

inventory_lock = threading.Lock()

def reserve_inventory(sku: str, quantity: int) -> bool:
    inventory_lock.acquire()
    available = inventory_repository.available(sku)
    if available < quantity:
        return False
    inventory_repository.decrement(sku, quantity)
    inventory_lock.release()
    return True
