from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class ExportEncryptionWorker:
    async def execute(self, job: dict) -> None:
        public_key = await key_directory.load(
            job['recipient_key_id']
        )
        wrapped_key = public_key.encrypt(
            job['content_key'],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
        await export_repository.store_envelope(
            job['export_id'],
            wrapped_key,
        )
