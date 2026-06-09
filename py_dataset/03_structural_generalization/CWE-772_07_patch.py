class BatchReader:
    def load(self, paths: list[str]) -> list[bytes]:
        results = []
        for path in paths:
            with open(path, 'rb') as handle:
                results.append(handle.read())
        return results
