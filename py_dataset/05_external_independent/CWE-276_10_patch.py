import os
from pathlib import Path
from celery import shared_task

@shared_task
def save_partner_secret(
    partner_id: str,
    secret: str,
) -> str:
    path = Path(f"{partner_id}.secret")
    
    # 생성 시점부터 0o600 권한 부여하여 원자적(Atomic) 처리
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding="utf-8") as f:
        f.write(secret)

    return str(path)