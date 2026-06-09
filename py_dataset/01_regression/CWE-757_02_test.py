SUPPORTED_ALGORITHMS = ['RSA-PSS-SHA256', 'RSA-PKCS1-SHA1']

def choose_signature_scheme(client_offers: list[str]) -> str:
    for offered in client_offers:
        if offered in SUPPORTED_ALGORITHMS:
            return offered
    raise ValueError("no shared algorithm")

def establish_channel(client_offers: list[str]):
    algorithm = choose_signature_scheme(client_offers)
    return crypto_backend.create_channel(algorithm)
