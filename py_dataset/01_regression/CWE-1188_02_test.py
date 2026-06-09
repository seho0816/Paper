import os

CHECK_EVENT_MAC = os.getenv("CHECK_EVENT_MAC", "off").lower() == "on"

def receive_event(body: bytes, signature: str) -> None:
    if CHECK_EVENT_MAC:
        verify_event_mac(body, signature)
    consume_event(body)
