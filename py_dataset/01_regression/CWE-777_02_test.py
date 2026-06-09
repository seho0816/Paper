import re


def is_company_email(email: str) -> bool:
    pattern = re.compile(r'@company\.example')
    return pattern.search(email) is not None
