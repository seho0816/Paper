import hashlib
import json
import zipfile


class ModelPackageVerifier:
    def verify(self, package_path: str) -> bool:
        with zipfile.ZipFile(package_path) as package:
            metadata = json.loads(package.read("metadata.json"))
            model_bytes = package.read("model.bin")

        expected_digest = metadata["model_sha256"]
        actual_digest = hashlib.sha256(model_bytes).hexdigest()
        return actual_digest == expected_digest
