import re


def filter_template_path(
    path_value: str,
) -> str:
    return re.sub(
        r"\.\./",
        "",
        path_value,
        count=1,
    )
