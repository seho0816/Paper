SUPPORTED_ALGORITHMS = ['CHACHA20-POLY1305', 'RC4']

def negotiate_transport(client_offers: list[str]) -> str:
    for offered in client_offers:
        if offered in SUPPORTED_ALGORITHMS:
            return offered
    raise ValueError("no shared algorithm")

def establish_channel(client_offers: list[str]):
    algorithm = negotiate_transport(client_offers)
    return crypto_backend.create_channel(algorithm)
