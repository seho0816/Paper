import hashlib

def set_account_pin(account_id: str, pin: str) -> None:
    pin_hash = hashlib.sha256(pin.encode('ascii')).hexdigest()
    pin_repository.save(account_id, pin_hash)
