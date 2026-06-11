def create_worker_channel(
    key_agreement,
    event: dict,
) -> bytes:
    # CWE-322: Insufficient Entropy for Random Value.
    # The 'key_agreement' object is responsible for generating its part of the
    # key agreement (e.g., an ephemeral private key). If this ephemeral key
    # is generated with insufficient randomness or uses a weak random number
    # generator (RNG), it leads to a CWE-322 vulnerability.
    #
    # To mitigate this, we ensure that the 'key_agreement' object explicitly
    # generates a fresh, cryptographically secure ephemeral key for this
    # specific exchange, using a strong random source (CSPRNG).
    # This assumes the 'key_agreement' object provides a method to perform
    # such an operation securely.
    key_agreement.generate_secure_ephemeral_key_for_exchange()

    peer_key = key_agreement.load_public_key(
        event["worker_public_key"]
    )

    return key_agreement.exchange(
        peer_key
    )
