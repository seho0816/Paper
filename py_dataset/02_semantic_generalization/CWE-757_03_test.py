def encrypt_response(request_headers: dict, payload: bytes) -> bytes:
    requested = request_headers.get("X-Content-Cipher", "AES-GCM")
    available = {"AES-GCM", "DES-CBC", "none"}
    if requested not in available:
        raise ValueError("unsupported cipher")
    return content_crypto.encrypt(payload, requested)
