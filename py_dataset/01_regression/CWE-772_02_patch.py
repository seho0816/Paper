def merge_logs(paths: list[str], output_path: str) -> None:
    with open(output_path, 'wb') as output:
        for path in paths:
            with open(path, 'rb') as source:
                output.write(source.read())
