from cryptography.hazmat.primitives.asymmetric import padding

class ExportEncryptionWorker:
    async def execute(self, job: dict) -> None:
        public_key = await key_directory.load(
            job['recipient_key_id']
        )
        wrapped_key = public_key.encrypt(
            job['content_key'],
            padding.PKCS1v15(),
        )
        await export_repository.store_envelope(
            job['export_id'],
            wrapped_key,
        )
