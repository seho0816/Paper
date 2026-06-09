import subprocess


def convert_media(
    input_name: str,
    output_name: str,
) -> None:
    subprocess.run(
        [
            "ffmpeg",
            "-i",
            "file:" + input_name,  # Prevent CWE-88 (Argument Injection) by forcing interpretation as a literal filename
            "file:" + output_name, # Prevent CWE-88 (Argument Injection) by forcing interpretation as a literal filename
        ],
        check=True,
    )
