def read_reports(paths: list[str]) -> list[str]:
    contents = []
    for path in paths:
        with open(path, 'r', encoding='utf-8') as file:
            contents.append(file.read())
    return contents

