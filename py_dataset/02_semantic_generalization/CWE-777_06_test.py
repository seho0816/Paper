import re


def requires_step_up_auth(path: str) -> bool:
    sensitive_pattern = re.compile(
        r'/admin/settings'
    )
    return sensitive_pattern.search(path) is not None
