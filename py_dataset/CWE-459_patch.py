from pathlib import Path
import tempfile
import os


class InvoiceDownloadJob:
    def create_csv_file(self, invoice_rows: list[str]) -> Path:
        # CWE-459: Incomplete Cleanup.
        # The original code created a file with a fixed name in the system's temporary directory.
        # This could lead to:
        # 1. Overwriting issues if called multiple times or concurrently.
        # 2. Accumulation of files that are never cleaned up, leading to disk space exhaustion.
        # 3. Predictable file names, which can be a security risk.
        #
        # To address this, we use `tempfile.mkstemp` to create a unique temporary file.
        # This ensures that each call generates a distinct file, preventing collisions and overwrites.
        # While `mkstemp` itself doesn't automatically delete the file, it provides a unique path
        # which can then be explicitly cleaned up by the application or a dedicated cleanup process
        # after the file has been downloaded or is no longer needed. This makes the cleanup manageable
        # unlike the fixed-name file which was harder to track and manage.

        # Create a unique temporary file. `mkstemp` returns a file descriptor and the path.
        fd, temp_path_str = tempfile.mkstemp(suffix=".csv", prefix="invoice_download_")
        output_path = Path(temp_path_str)

        try:
            # Open the file descriptor in text mode with utf-8 encoding to write the content.
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp_file:
                tmp_file.write("\n".join(invoice_rows))
        except Exception:
            # If an error occurs during writing, ensure the created temporary file is removed
            # to prevent orphaned or corrupt files from lingering.
            os.remove(output_path)
            raise
        
        # The unique temporary file now exists at `output_path`.
        # The responsibility for its eventual cleanup (e.g., via `os.remove(output_path)`)
        # lies with the component that consumes `download_path` after the file has been used.
        return output_path

    def create_download_response(self, invoice_rows: list[str]) -> dict[str, str]:
        path = self.create_csv_file(invoice_rows)
        return {
            "download_path": str(path),
        }


def main() -> None:
    job = InvoiceDownloadJob()
    print(job.create_download_response(["id,amount", "INV-1,30000"]))


if __name__ == "__main__":
    main()
