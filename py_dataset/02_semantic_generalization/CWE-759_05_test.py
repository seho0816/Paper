import hashlib

def import_accounts(rows: list[dict]) -> None:
    for row in rows:
        digest = hashlib.sha256(row['password'].encode('utf-8')).hexdigest()
        account_repository.create(row['email'], digest)
