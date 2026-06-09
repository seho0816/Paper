import subprocess


def run_document_converter(
    input_path: str,
) -> None:
    subprocess.run(
        [
            "/opt/tools/document-converter",
            input_path,
        ],
        close_fds=True,
        check=True,
    )

