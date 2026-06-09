class ResponseObject:
    def __init__(self) -> None:
        self.payload = {}


object_pool: list[ResponseObject] = []


def build_order_summary(order: dict) -> dict:
    wrapper = object_pool.pop() if object_pool else ResponseObject()
    # CWE-226 fix: Clear the payload to ensure no sensitive data from previous uses leaks.
    # This prevents information from a prior request from being present in the current response.
    wrapper.payload = {}
    wrapper.payload["order_id"] = order["id"]
    wrapper.payload["status"] = order["status"]
    return wrapper.payload
