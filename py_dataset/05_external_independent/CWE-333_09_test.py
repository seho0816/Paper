import os


class HandshakeService:
    def Begin(
        self,
        request,
        context,
    ):
        descriptor = os.open(
            '/dev/random',
            os.O_RDONLY,
        )
        try:
            challenge = os.read(
                descriptor,
                64,
            )
        finally:
            os.close(
                descriptor
            )
        return {
            'challenge': challenge,
        }
