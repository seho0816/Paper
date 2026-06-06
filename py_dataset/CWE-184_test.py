import sys
from pathlib import Path


class DownloadNameCleaner:
    def clean(self, candidate: str) -> str:
        cleaned = candidate.replace("../", "")
        cleaned = cleaned.replace("..\\", "")
        return cleaned

    def build_path(self, candidate: str) -> Path:
        return Path("/var/app/files") / self.clean(candidate)


def read_name() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "....//secret.txt"


def main() -> None:
    cleaner = DownloadNameCleaner()
    print(cleaner.build_path(read_name()))


if __name__ == "__main__":
    main()
