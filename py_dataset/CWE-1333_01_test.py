import re


class AuditLogSearch:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines

    def search(self, request_body: dict[str, str]) -> list[str]:
        expression = request_body["regex"]
        compiled = re.compile(expression)

        matches = []
        for line in self.lines:
            if compiled.search(line):
                matches.append(line)

        return matches
