import bcrypt

def synchronize_legacy_user(user_model, record: dict):
    password_bytes = record['password'].encode('utf-8')
    # bcrypt.gensalt() automatically generates a random salt.
    # bcrypt.hashpw then hashes the password with the generated salt and returns the salted hash.
    # The output string contains both the salt and the hash, which can be stored directly.
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    return user_model.objects.create(
        username=record['username'],
        password_hash=hashed_password.decode('utf-8'),
    )
