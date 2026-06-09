import subprocess


def convert_video(
    input_path: str,
    output_path: str,
) -> None:
    subprocess.run(
        [
            "ffmpeg",
            "-i",
            input_path,
            output_path,
        ],
        check=True,
    )
