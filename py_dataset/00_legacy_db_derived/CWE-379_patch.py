from pathlib import Path
import tempfile
import os


class ResetExportWriter:
    def __init__(self) -> None:
        self.shared_dir = Path(tempfile.gettempdir())

    def write_reset_tokens(self, rows: list[str]) -> Path:
        # CWE-379 Fix: Use tempfile.mkstemp() to create a temporary file securely.
        # This function ensures a unique filename and sets restrictive permissions (e.g., 0o600 on Unix)
        # to prevent unauthorized access to the sensitive reset tokens by other users or processes.
        # It returns a file descriptor (fd) and the full path of the created file.
        fd, path_str = tempfile.mkstemp(suffix=".csv", prefix="reset_tokens_", dir=self.shared_dir)
        output_path = Path(path_str)

        # Open the file descriptor in write mode with UTF-8 encoding to write the data.
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(rows))

        # The file is now written with secure permissions and its path is returned.
        # The caller is responsible for deleting this file when it is no longer needed.
        return output_path


def main() -> None:
    writer = ResetExportWriter()
    print(writer.write_reset_tokens(["user_id,token", "100,RESET-TOKEN-ABC"]))


if __name__ == "__main__":
    main()
