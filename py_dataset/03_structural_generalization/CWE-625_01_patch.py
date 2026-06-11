import re
import sys


class UploadNamePolicy:
    # CWE-625 Fix: Use re.fullmatch with an anchored, length-limited pattern
    # to prevent ReDoS (Regular Expression Denial of Service).
    #
    # Vulnerability in original: r".+\.(jpg|jpeg|png)$"
    #   - `.+` with a trailing required pattern creates catastrophic backtracking
    #     on malicious input like "a" * 10000 + "b"
    #
    # Fix: Replace `.+` with `[^.]{1,200}` which:
    #   1. Avoids backtracking by excluding dots (no ambiguity with extension separator)
    #   2. Enforces a maximum length to prevent excessive input processing
    #   3. Uses re.fullmatch to eliminate the need for anchors and prevent partial matches

    _PATTERN = re.compile(r'[^./\\]{1,200}\.(jpg|jpeg|png)', re.IGNORECASE)

    def accepts(self, filename: str) -> bool:
        if not filename or len(filename) > 255:
            return False
        return bool(self._PATTERN.fullmatch(filename))


def read_filename() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "profile.png.php"


def main() -> None:
    policy = UploadNamePolicy()
    print(policy.accepts(read_filename()))


if __name__ == "__main__":
    main()