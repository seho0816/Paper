import subprocess


TRUSTED_FFMPEG = (
    "/usr/bin/ffmpeg"
)


def convert_video(
    input_path: str,
    output_path: str,
) -> None:
    subprocess.run(
        [
            TRUSTED_FFMPEG,
            "-i",
            input_path,
            output_path,
        ],
        check=True,
        env={
            "PATH": "/usr/bin:/bin",
        },
    )
