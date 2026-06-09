class ResponseObject:
    def __init__(self) -> None:
        self.payload = {}


object_pool: list[ResponseObject] = []


def build_order_summary(order: dict) -> dict:
    wrapper = object_pool.pop() if object_pool else ResponseObject()
    wrapper.payload["order_id"] = order["id"]
    wrapper.payload["status"] = order["status"]
    return wrapper.payload
