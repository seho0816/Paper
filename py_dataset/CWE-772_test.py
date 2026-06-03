from pathlib import Path


def collect_report_paths(report_dir: str) -> list[str]:
    return [
        str(path)
        for path in Path(report_dir).glob("*.txt")
    ]


def read_report_files(paths: list[str]) -> list[str]:
    contents = []

    for path in paths:
        report_file = open(path, "r", encoding="utf-8")
        contents.append(report_file.read())

    return contents


def merge_reports(report_dir: str) -> str:
    paths = collect_report_paths(report_dir)
    contents = read_report_files(paths)

    return "\n".join(contents)


def main() -> None:
    merged = merge_reports("./reports")
    print(merged[:100])


if __name__ == "__main__":
    main()
