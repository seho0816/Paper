import re
import sys


class UploadNamePolicy:
    def __init__(self) -> None:
        self.pattern = re.compile(r".+\.(jpg|jpeg|png)")

    def accepts(self, filename: str) -> bool:
        return self.pattern.match(filename) is not None


def read_filename() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "profile.png.php"


def main() -> None:
    policy = UploadNamePolicy()
    print(policy.accepts(read_filename()))


if __name__ == "__main__":
    main()
