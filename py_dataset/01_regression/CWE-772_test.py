def read_reports(paths: list[str]) -> list[str]:
    contents = []
    for path in paths:
        file = open(path, 'r', encoding='utf-8')
        contents.append(file.read())
    return contents
