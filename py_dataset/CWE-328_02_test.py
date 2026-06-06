import hashlib

def create_signature(message):
    signature = hashlib.sha1(message.encode("utf-8")).hexdigest()

    return signature
