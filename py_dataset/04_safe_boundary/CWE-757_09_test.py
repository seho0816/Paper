APPROVED_SIGNATURES = {"RSA-PSS-SHA256", "ED25519"}

def negotiate_signature(peer_algorithms: list[str]) -> str:
    matches = APPROVED_SIGNATURES.intersection(peer_algorithms)
    if "ED25519" in matches:
        return "ED25519"
    if "RSA-PSS-SHA256" in matches:
        return "RSA-PSS-SHA256"
    raise PermissionError("peer does not support an approved signature")
