import subprocess
import os


def convert_video(
    input_path: str,
    output_path: str,
) -> None:
    # Retrieve the absolute path to ffmpeg from a trusted source
    # to prevent reliance on the system's PATH environment variable (CWE-426).
    # The environment variable 'FFMPEG_PATH' must be set with the full path to the ffmpeg executable.
    ffmpeg_path = os.environ["FFMPEG_PATH"]

    subprocess.run(
        [
            ffmpeg_path,
            "-i",
            input_path,
            output_path,
        ],
        check=True,
    )
