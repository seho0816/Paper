import os
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class SessionRequest:
    client_address: str


class AnonymousSessionFactory:
    def create(
        self,
        request: SessionRequest,
    ) -> dict:
        # CWE-333: Inadequate Entropy in PRNG
        # Directly reading from /dev/random can block or behave inconsistently across OS.
        # It's better to use Python's built-in cryptographically secure random number
        # generator via the 'secrets' module, which internally uses os.urandom().
        # This provides sufficient entropy and is non-blocking and cross-platform.
        session_id = secrets.token_hex(48)
        return {
            'session_id': session_id,
            'client_address': request.client_address,
        }
