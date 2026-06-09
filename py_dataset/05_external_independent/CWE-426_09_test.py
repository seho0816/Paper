import shutil
import subprocess


def run_converter(
    source: str,
    destination: str,
) -> None:
    executable = shutil.which(
        "document-converter"
    )

    subprocess.run(
        [
            executable,
            source,
            destination,
        ],
        check=True,
    )
