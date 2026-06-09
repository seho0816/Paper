import json


def run_event_worker(messages: list[bytes]) -> None:
    for raw_message in messages:
        try:
            event = json.loads(raw_message)
            dispatch_event(event)
        except Exception:
            # CWE-248 fix: JSON 파싱 및 dispatch_event에서 발생하는
            # 모든 예외를 포착하여 워커가 중단되지 않도록 처리
            pass