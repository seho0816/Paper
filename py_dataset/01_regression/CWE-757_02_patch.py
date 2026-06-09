import crypto_backend

SUPPORTED_ALGORITHMS = ['RSA-PSS-SHA256', 'RSA-PKCS1-SHA1']

# Define a preference order for algorithms to prevent downgrade attacks (CWE-757).
# Higher values indicate more preferred (more secure) algorithms.
ALGORITHM_PREFERENCE = {
    'RSA-PSS-SHA256': 100, # This is the more secure option.
    'RSA-PKCS1-SHA1': 10,  # SHA-1 is cryptographically weaker and should be a fallback or avoided.
}

def choose_signature_scheme(client_offers: list[str]) -> str:
    # Filter client offers to only include algorithms that are supported by the system.
    negotiable_algorithms = [
        alg for alg in client_offers if alg in SUPPORTED_ALGORITHMS
    ]

    if not negotiable_algorithms:
        raise ValueError("no shared algorithm")

    # Sort the negotiable algorithms by their preference score in descending order.
    # This ensures that the most secure (highest preference) common algorithm is chosen.
    negotiable_algorithms.sort(key=lambda alg: ALGORITHM_PREFERENCE.get(alg, 0), reverse=True)

    # Return the most preferred algorithm among the shared ones.
    return negotiable_algorithms[0]

def establish_channel(client_offers: list[str]):
    algorithm = choose_signature_scheme(client_offers)
    return crypto_backend.create_channel(algorithm)
