import hashlib

pending_secret_retries: list[dict] = []


def validate_api_secret(client_id: str, secret: str) -> bool:
    # CWE-316: Cleartext Storage of Sensitive Information in a Queue
    # The 'secret' should not be stored in cleartext in 'pending_secret_retries'.
    # Instead, a non-reversible hash of the secret is stored for tracking/auditing purposes,
    # preventing cleartext exposure if the 'pending_secret_retries' list is compromised.
    # This change specifically addresses the cleartext storage vulnerability.
    # The original cleartext 'secret' is still passed to api_client_repository.verify()
    # as required by its presumed functionality.
    hashed_secret = hashlib.sha256(secret.encode('utf-8')).hexdigest()
    pending_secret_retries.append({'client_id': client_id, 'secret_hash': hashed_secret})
    
    # Assuming api_client_repository is defined elsewhere and handles API client verification.
    # This part of the code is not part of the CWE-316 vulnerability and is kept as-is.
    return api_client_repository.verify(client_id, secret)
