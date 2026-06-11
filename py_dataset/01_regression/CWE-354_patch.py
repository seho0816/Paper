import hashlib
import json
import zipfile
import secrets

def verify_uploaded_archive(
    archive_path: str,
) -> bool:
    with zipfile.ZipFile(
        archive_path
    ) as archive:
        manifest_content_bytes = archive.read(
            "manifest.json"
        )
        manifest = json.loads(
            manifest_content_bytes
        )
        payload = archive.read(
            "payload.json"
        )

    # CWE-354: 데이터와 매니페스트를 함께 해싱하여 무결성을 보장하고 안전한 비교 연산 수행
    actual_hash = hashlib.sha256(
        manifest_content_bytes + payload
    ).hexdigest()

    return secrets.compare_digest(
        actual_hash,
        manifest.get("sha256", "")
    )