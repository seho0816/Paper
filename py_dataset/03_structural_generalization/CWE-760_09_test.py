import hashlib

class ImportedAccountFactory:
    def create(self, row_number: int, record: dict) -> dict:
        salt = f'import-{row_number}'.encode('ascii')
        digest = hashlib.pbkdf2_hmac(
            'sha256',
            record['password'].encode('utf-8'),
            salt,
            600_000,
        )
        return {'email': record['email'], 'password_hash': digest}
