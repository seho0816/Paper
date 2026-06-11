import os

# CWE-1188: Inadequate Encryption Strength.
# In this context, the vulnerability arises from the authentication mechanism being optional and easily bypassable
# via an environment variable, leading to inadequate authentication strength by default or misconfiguration.
# To ensure robust authentication, the callback authentication is now unconditionally required.
REQUIRE_CALLBACK_AUTH = True

def receive_event(body: bytes, signature: str) -> None:
    if REQUIRE_CALLBACK_AUTH:
        authenticate_callback(body, signature)
    handle_callback(body)
