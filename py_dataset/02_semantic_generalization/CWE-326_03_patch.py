from cryptography.hazmat.primitives.asymmetric import dh


def create_exchange_parameters():
    return dh.generate_parameters(
        generator=2,
        key_size=2048,
    )
