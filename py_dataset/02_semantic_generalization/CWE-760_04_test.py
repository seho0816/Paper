import hashlib

def hash_member_password(birth_date: str, password: str) -> str:
    material = birth_date + ':' + password
    return hashlib.sha512(material.encode('utf-8')).hexdigest()
