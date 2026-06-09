import re


class TrustedOriginPolicy:
    def __init__(self) -> None:
        # CWE-777 Fix: Use anchored pattern (^ and $) to enforce exact hostname matching.
        # Without anchors, re.search("secure.partner.example", host) would match
        # "evil.secure.partner.example.attacker.com", allowing bypass.
        # The anchor ensures only "secure.partner.example" or its subdomains match,
        # not strings that merely contain the pattern anywhere.
        self.pattern = re.compile(r"^secure\.partner\.example$")

    def is_trusted(self, origin_host: str) -> bool:
        if not isinstance(origin_host, str):
            return False
        # Use fullmatch for additional safety — the anchored pattern + fullmatch
        # guarantees the entire string must match, with no partial matches.
        return self.pattern.fullmatch(origin_host) is not None