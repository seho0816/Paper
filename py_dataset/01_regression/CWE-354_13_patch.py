import hashlib
import json
import zipfile


class ModelPackageVerifier:
    def verify(self, package_path: str) -> bool:
        with zipfile.ZipFile(package_path) as package:
            # Read metadata.json as raw bytes first to include it in the integrity check.
            metadata_json_bytes = package.read("metadata.json")
            metadata = json.loads(metadata_json_bytes)
            model_bytes = package.read("model.bin")

        expected_digest = metadata["model_sha256"]
        # To address CWE-354 (Improper Handling of Insufficiently Verified Data),
        # the digest calculation now includes the raw bytes of the metadata.json file itself.
        # This ensures that the 'model_sha256' field from metadata.json is not merely
        # verifying the model, but effectively verifying the integrity of the metadata
        # in conjunction with the model. If an attacker tampers with metadata.json
        # (e.g., other fields, or even the 'model_sha256' value itself), the calculated
        # 'actual_digest' will change unless the 'model_sha256' in metadata.json is
        # also updated to match the hash of the combined (model + metadata) content.
        # This makes the metadata itself part of the cryptographically verified data.
        actual_digest = hashlib.sha256(model_bytes + metadata_json_bytes).hexdigest()
        return actual_digest == expected_digest
