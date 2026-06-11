import tempfile
import os

def write_rendered_report(
    rendered_html: str,
) -> str:
    # CWE-377: mktemp 대신 안전한 mkstemp를 사용하고 fd를 즉시 랩핑
    fd, temp_path = tempfile.mkstemp(
        prefix="report_",
        suffix=".html",
    )

    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(
            rendered_html
        )

    return temp_path