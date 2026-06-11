from pathlib import Path

BACKUP_ROOT = Path(
    "/var/backups/application"
)

def list_backups() -> list[dict]:
    result = []
    # CWE-200: 민감한 숨김 파일(예: .env, .config) 노출 방지
    for path in BACKUP_ROOT.iterdir():
        if path.is_file() and not path.name.startswith('.'):
            result.append({
                "name": path.name,
                "size": path.stat().st_size,
            })
    return result