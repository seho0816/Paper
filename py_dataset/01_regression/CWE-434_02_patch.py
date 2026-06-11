from pathlib import Path

UPLOAD_DIR = Path("/var/app/uploads")
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.pdf', '.txt'}

def save_uploaded_file(
    filename: str,
    content: bytes,
) -> str:
    safe_filename = Path(filename).name
    file_suffix = Path(safe_filename).suffix.lower()

    # CWE-434: 안전한 파일 확장자인지 명시적으로 검사
    if not file_suffix or file_suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type '{file_suffix}' is not allowed for upload.")

    target_path = UPLOAD_DIR / safe_filename
    target_path.write_bytes(content)

    return str(target_path)