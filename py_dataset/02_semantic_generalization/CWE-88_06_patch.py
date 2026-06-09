import subprocess


def create_certificate_request(
    subject: str,
    output_path: str,
) -> None:
    # CWE-88: Improper Neutralization of Argument Delimiters in a Command
    # The 'subject' and 'output_path' parameters are passed directly to openssl,
    # a C-based command-line utility. C functions typically treat null bytes (\x00)
    # as string terminators. If an attacker injects a null byte into these strings,
    # openssl might process only the part of the string before the null byte,
    # leading to truncation or unintended command interpretation (e.g., if the
    # truncated string then forms a valid command-line argument).
    # To mitigate this, remove any null bytes from the input strings.
    safe_subject = subject.replace('\x00', '')
    safe_output_path = output_path.replace('\x00', '')

    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-subj",
            safe_subject,
            "-out",
            safe_output_path,
        ],
        check=True,
    )
