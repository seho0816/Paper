class CipherSuiteRegistry:
    def __init__(self) -> None:
        self._factories = {
            'CHACHA20-POLY1305': (
                create_chacha20_suite
            ),
            # RC4 is a known weak cipher and has been removed to prevent algorithm downgrade attacks (CWE-757).
        }

    def create_first_match(
        self,
        client_hello: dict,
    ):
        for name in client_hello.get(
            'cipher_suites',
            [],
        ):
            factory = self._factories.get(
                name
            )

            if factory is not None:
                return factory()

        raise PermissionError(
            'cipher negotiation failed'
        )


class HandshakeSession:
    def receive_client_hello(
        self,
        message: dict,
    ) -> None:
        self.cipher_suite = (
            CipherSuiteRegistry()
            .create_first_match(message)
        )
        self.state = 'cipher_selected'
