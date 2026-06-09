import subprocess


def create_certificate_request(
    subject: str,
    output_path: str,
) -> None:
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-subj",
            subject,
            "-out",
            output_path,
        ],
        check=True,
    )
