import urllib.parse

def sanitize_storage_key(
    storage_key: str,
) -> str:
    # 1. URL 디코딩을 수행하여 %2e%2e%2f (../) 등 인코딩된 경로 탐색 시퀀스를 처리합니다.
    cleaned = urllib.parse.unquote(storage_key)

    # 2. Windows 스타일 백슬래시를 POSIX 스타일 포워드 슬래시로 변환합니다.
    #    이는 `..\` 같은 경로 탐색 시퀀스를 처리하는 데 도움이 됩니다.
    cleaned = cleaned.replace("\\", "/")

    # 3. 이중 슬래시 (//)를 단일 슬래시 (/)로 반복적으로 대체하여
    #    `s3://bucket///key`와 같은 불필요한 슬래시를 정규화하고,
    #    `....//` 와 같이 `../` 패턴을 숨기는 경우를 노출시킵니다.
    old_cleaned_slashes = None
    while old_cleaned_slashes != cleaned:
        old_cleaned_slashes = cleaned
        cleaned = cleaned.replace("//", "/")

    # 4. `../` 패턴을 반복적으로 제거합니다.
    #    이것이 CWE-184(불완전한 블랙리스트) 취약점의 핵심 수정 사항입니다.
    #    `.../` 또는 `..../`와 같이 첫 번째 교체 후 `../`로 해결될 수 있는
    #    모든 형태의 `../`를(디코딩 및 슬래시 정규화 후) 제거하도록 보장합니다.
    old_cleaned_dots = None
    while old_cleaned_dots != cleaned:
        old_cleaned_dots = cleaned
        cleaned = cleaned.replace("../", "")

    return cleaned
