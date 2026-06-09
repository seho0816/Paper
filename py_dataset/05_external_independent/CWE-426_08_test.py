import subprocess


def render_pdf(
    source_url: str,
    output_path: str,
) -> None:
    process = subprocess.Popen([
        "wkhtmltopdf",
        source_url,
        output_path,
    ])
    process.wait()
