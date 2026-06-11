import crypto_backend

SUPPORTED_ALGORITHMS = ['AES-256-GCM', '3DES-CBC']

def select_export_cipher(client_offers: list[str]) -> str:
    for preferred_alg in SUPPORTED_ALGORITHMS:
        if preferred_alg in client_offers:
            return preferred_alg
    raise ValueError("no shared algorithm")

def establish_channel(client_offers: list[str]):
    algorithm = select_export_cipher(client_offers)
    return crypto_backend.create_channel(algorithm)
