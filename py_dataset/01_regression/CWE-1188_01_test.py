import os

REQUIRE_CALLBACK_AUTH = os.getenv("REQUIRE_CALLBACK_AUTH", "0") == "1"

def receive_event(body: bytes, signature: str) -> None:
    if REQUIRE_CALLBACK_AUTH:
        authenticate_callback(body, signature)
    handle_callback(body)
