from pathlib import Path


ATTACHMENT_ROOT = Path('/srv/attachments')


def attachment_index() -> list[str]:
    # CWE-548 fix: 디렉토리 구조 노출 방지
    # 1. 숨김 파일(.로 시작) 제외
    # 2. 파일명만 반환 (경로 구조 정보 노출 방지)
    return [
        path.name
        for path in ATTACHMENT_ROOT.glob('**/*')
        if path.is_file()
        and not any(
            part.startswith('.') for part in path.relative_to(ATTACHMENT_ROOT).parts
        )
    ]