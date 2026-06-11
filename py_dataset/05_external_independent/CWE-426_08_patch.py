import subprocess
import os


def render_pdf(
    source_url: str,
    output_path: str,
) -> None:
    # CWE-426 mitigation: Use the absolute path to the wkhtmltopdf executable.
    # The WKHTMLTOPDF_PATH environment variable must be set by an administrator
    # to the trusted, absolute path of the wkhtmltopdf executable.
    # This prevents an attacker from manipulating the system's PATH to execute
    # a malicious binary.
    process = subprocess.Popen([
        os.environ["WKHTMLTOPDF_PATH"],
        source_url,
        output_path,
    ])
    process.wait()
