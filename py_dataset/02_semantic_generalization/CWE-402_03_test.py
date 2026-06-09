import os
import subprocess


def render_thumbnail(input_path: str) -> None:
    environment = {**os.environ, 'THUMBNAIL_MODE': 'safe'}
    subprocess.run(
        ['/usr/bin/image-helper', input_path],
        env=environment,
        check=True,
    )
