SERVER_PREFERENCE = (
    "AES-256-GCM",
    "CHACHA20-POLY1305",
)

def select_cipher(client_offers: list[str]) -> str:
    offered = set(client_offers)
    for algorithm in SERVER_PREFERENCE:
        if algorithm in offered:
            return algorithm
    raise ValueError("no acceptable secure cipher")
