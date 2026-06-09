class BatchReader:
    def load(self, paths: list[str]) -> list[bytes]:
        opened = []
        results = []
        for path in paths:
            handle = open(path, 'rb')
            opened.append(handle)
            results.append(handle.read())
        return results
