import json


def restore_background_job(
    serialized_job: str,
) -> object:
    # CWE-502: Bandit(B301) 경고 우회 및 안전한 역직렬화를 위해 jsonpickle 대신 내장 json 사용
    return json.loads(
        serialized_job,
    )