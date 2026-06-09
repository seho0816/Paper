import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SessionRequest:
    client_address: str


class AnonymousSessionFactory:
    def create(
        self,
        request: SessionRequest,
    ) -> dict:
        descriptor = os.open(
            '/dev/random',
            os.O_RDONLY,
        )
        try:
            session_id = os.read(
                descriptor,
                48,
            ).hex()
        finally:
            os.close(
                descriptor
            )
        return {
            'session_id': session_id,
            'client_address': request.client_address,
        }
