def merge_logs(paths: list[str], output_path: str) -> None:
    sources = [open(path, 'rb') for path in paths]
    with open(output_path, 'wb') as output:
        for source in sources:
            output.write(source.read())
