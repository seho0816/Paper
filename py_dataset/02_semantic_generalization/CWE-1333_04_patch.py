import re


LOG_PATTERN = re.compile(
    r"^(.*?a){10}$"
)


def parse_log_line(
    line: str,
) -> bool:
    return (
        LOG_PATTERN.match(
            line,
        )
        is not None
    )
