import subprocess


def encrypt_backup(backup_path: str, encryption_key: str) -> None:
    # The original code passed the encryption_key directly as a command-line argument.
    # This method can expose sensitive information like encryption keys
    # in process listings (e.g., `ps aux`), system logs, or shell history.
    # While subprocess.run with a list of arguments generally prevents
    # OS command injection (CWE-78) by not using a shell,
    # the exposure of sensitive data on the command line can be considered
    # an "Improper Control of Generation of Code" (CWE-214) in the sense
    # that the process invocation (the "code" being "generated")
    # is handled insecurely, leading to unintended information disclosure.
    #
    # To mitigate this, the encryption key should be passed through a more
    # secure channel, such as standard input (stdin). This prevents the key
    # from appearing in the command-line arguments.
    # This patch assumes that the 'backup-encrypt' utility supports
    # reading the encryption key from stdin when the '--key' argument is omitted.
    subprocess.run(
        ["backup-encrypt", backup_path],
        input=encryption_key.encode('utf-8'),  # Pass the key via stdin
        check=True,
    )
