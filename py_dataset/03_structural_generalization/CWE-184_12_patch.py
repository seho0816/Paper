import sys
from pathlib import Path


class DownloadNameCleaner:
    def clean(self, candidate: str) -> str:
        # Convert all backslashes to forward slashes for consistent processing across OS
        normalized_candidate = candidate.replace("\\", "/")

        # Use pathlib to parse the path into components.
        # This handles multiple slashes (e.g., `//`) robustly.
        p = Path(normalized_candidate)

        cleaned_parts = []
        for part in p.parts:
            # Skip the root/anchor part (e.g., '/' for Unix, 'C:/' for Windows)
            # to ensure the resulting path is always relative.
            if part == p.anchor:
                continue
            
            # Filter out '.' and '..' components to prevent path traversal.
            # Also, filter out empty strings that might result from consecutive slashes,
            # though pathlib.parts usually handles this by not creating empty parts for `//`.
            if part in ('.', '..') or not part:
                continue
            
            cleaned_parts.append(part)
        
        # Reconstruct the path string from the cleaned components.
        # If no valid parts remain (e.g., candidate was "/", "../", "....//"), return an empty string.
        if not cleaned_parts:
            return ""

        # Join parts with '/' to create a normalized, relative path string.
        return "/".join(cleaned_parts)

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
