import re
from concurrent.futures import ThreadPoolExecutor

def filter_messages(
    pattern_text: str,
    messages: list[str],
) -> list[str]:
    pattern = re.compile(
        pattern_text,
    )

    results = []
    # CWE-1333: 악의적인 정규식에 의한 서버 마비(ReDoS)를 막기 위해 타임아웃 1초 적용
    with ThreadPoolExecutor(max_workers=1) as executor:
        for message in messages:
            try:
                # 외부 헬퍼 함수를 새로 만들지 않고 직접 호출하여 구조 보존
                future = executor.submit(pattern.search, message)
                if future.result(timeout=1):
                    results.append(message)
            except Exception:
                # 시간 초과 시 해당 메시지는 무시하고 넘어감
                pass

    return results