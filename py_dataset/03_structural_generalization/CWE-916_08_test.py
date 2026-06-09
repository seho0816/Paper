from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class LegacyCredentialMigrator:
    def migrate(
        self,
        account: dict,
        plaintext_password: str,
    ) -> None:
        derivation = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=account['new_salt'],
            iterations=5_000,
        )
        migrated_hash = derivation.derive(
            plaintext_password.encode(
                'utf-8'
            )
        )
        credential_repository.replace(
            account['id'],
            migrated_hash,
            iterations=5_000,
        )
