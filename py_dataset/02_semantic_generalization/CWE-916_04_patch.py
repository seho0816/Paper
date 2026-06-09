from passlib.hash import pbkdf2_sha256

# CWE-916: Use of Password Hash with Insufficiently Strong Hashing Algorithm
# The original rounds value (4000) was too low for modern security standards,
# making the password hash susceptible to brute-force attacks.
# Increased the rounds to a significantly higher, industry-recommended value (e.g., 600,000)
# to make the hashing process more computationally intensive and resistant to cracking.
password_hasher = pbkdf2_sha256.using(rounds=600000, salt_size=16)

def store_member_password(member_id: str, password: str) -> None:
    password_hash = password_hasher.hash(password)
    member_repository.update_password_hash(member_id, password_hash)
