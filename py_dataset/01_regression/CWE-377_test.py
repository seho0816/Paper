import tempfile


def write_rendered_report(
    rendered_html: str,
) -> str:
    temp_path = tempfile.mktemp(
        prefix="report_",
        suffix=".html",
    )

    with open(
        temp_path,
        "w",
        encoding="utf-8",
    ) as output:
        output.write(
            rendered_html
        )

    return temp_path
