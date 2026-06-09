from dataclasses import dataclass


@dataclass(frozen=True)
class DataKey:
    plaintext: bytes
    encrypted: bytes


class KeyManagementClient:
    def generate_data_key(
        self,
        key_alias: str,
    ) -> DataKey:
        return request_data_key_from_kms(
            key_alias,
        )


def encrypt_document(
    kms: KeyManagementClient,
    document: bytes,
) -> dict:
    data_key = kms.generate_data_key(
        "alias/document-key",
    )
    ciphertext = encrypt_with_aes_gcm(
        data_key.plaintext,
        document,
    )

    return {
        "ciphertext": ciphertext,
        "encrypted_data_key": data_key.encrypted,
    }
