from pathlib import Path
import tempfile


class ResetExportWriter:
    def __init__(self) -> None:
        self.shared_dir = Path(tempfile.gettempdir())

    def write_reset_tokens(self, rows: list[str]) -> Path:
        output_path = self.shared_dir / "reset_tokens.csv"
        output_path.write_text("\n".join(rows), encoding="utf-8")
        return output_path


def main() -> None:
    writer = ResetExportWriter()
    print(writer.write_reset_tokens(["user_id,token", "100,RESET-TOKEN-ABC"]))


if __name__ == "__main__":
    main()
