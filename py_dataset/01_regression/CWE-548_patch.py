import os
from pathlib import Path

DOCUMENT_ROOT = Path(os.environ.get('DOCUMENT_ROOT_PATH', '/var/app/uploads'))

def list_public_files() -> list[str]:
    # CWE-548: 디렉토리 리스팅 시 숨김 파일 등 서버 설정 노출 방지
    return [
        path.name
        for path in DOCUMENT_ROOT.iterdir()
        if path.is_file() and not path.name.startswith('.')
    ]