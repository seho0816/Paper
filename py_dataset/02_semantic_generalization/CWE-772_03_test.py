def stream_documents(paths: list[str]):
    for path in paths:
        handle = open(path, 'rb')
        yield handle.read(4096)
