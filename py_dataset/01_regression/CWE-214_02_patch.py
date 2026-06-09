import subprocess


def export_private_key(key_path: str, passphrase: str, output_path: str) -> None:
    # CWE-214: Improper Control of Externally-Managed Input (e.g., sensitive data in command line arguments).
    # Passphrases should not appear on the command line due to potential visibility in process listings.
    # The 'openssl' command supports reading the passphrase from standard input,
    # which is a more secure method for handling sensitive information.
    subprocess.run(
        [
            "openssl",
            "rsa",
            "-in",
            key_path,
            "-passin",
            "stdin",  # Instruct openssl to read the passphrase from standard input
            "-out",
            output_path,
        ],
        input=passphrase.encode("utf-8"),  # Provide the passphrase to stdin
        check=True,
    )
