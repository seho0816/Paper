SUPPORTED_ALGORITHMS = ['AES-256-GCM', '3DES-CBC']

def select_export_cipher(client_offers: list[str]) -> str:
    for offered in client_offers:
        if offered in SUPPORTED_ALGORITHMS:
            return offered
    raise ValueError("no shared algorithm")

def establish_channel(client_offers: list[str]):
    algorithm = select_export_cipher(client_offers)
    return crypto_backend.create_channel(algorithm)
