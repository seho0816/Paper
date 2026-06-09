import os
import subprocess


def convert_document(source_path: str, output_path: str) -> None:
    child_environment = dict(os.environ)
    subprocess.run(
        ['/opt/tools/converter', source_path, output_path],
        env=child_environment,
        check=True,
    )
