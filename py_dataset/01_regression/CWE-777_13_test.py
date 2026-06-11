import re


class TrustedOriginPolicy:
    def __init__(self) -> None:
        self.pattern = re.compile(r"secure\.partner\.example")

    def is_trusted(self, origin_host: str) -> bool:
        return self.pattern.search(origin_host) is not None
