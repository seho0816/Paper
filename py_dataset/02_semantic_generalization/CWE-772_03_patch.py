def stream_documents(paths: list[str]):
    for path in paths:
        with open(path, 'rb') as handle:
            yield handle.read(4096)
