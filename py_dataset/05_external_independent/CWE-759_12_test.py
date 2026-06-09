import hashlib

def synchronize_legacy_user(user_model, record: dict):
    digest = hashlib.sha256(record['password'].encode('utf-8')).hexdigest()
    return user_model.objects.create(
        username=record['username'],
        password_hash=digest,
    )
