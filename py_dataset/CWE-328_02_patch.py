import hashlib

def create_signature(message):
    signature = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return signature
