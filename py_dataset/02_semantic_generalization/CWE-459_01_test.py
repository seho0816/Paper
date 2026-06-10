from pathlib import Path
import tempfile


class InvoiceDownloadJob:
    def create_csv_file(self, invoice_rows: list[str]) -> Path:
        work_dir = Path(tempfile.gettempdir())
        output_path = work_dir / "invoice_download.csv"
        output_path.write_text("\n".join(invoice_rows), encoding="utf-8")
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
