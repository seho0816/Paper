import re


def is_company_email(email: str) -> bool:
    # CWE-777: Polymorphic Typing
    # The vulnerability arises if the 'email' parameter,
    # despite its type hint, could be an object of a different type
    # that is then processed in an unexpected or malicious way
    # (e.g., through a custom __str__ method) when passed to re.search().
    #
    # To mitigate this, explicitly ensure that 'email' is indeed a string.
    # If it's not a string, return False immediately to prevent unexpected
    # object method calls or type errors during regex processing.
    if not isinstance(email, str):
        return False

    pattern = re.compile(r'@company\.example')
    return pattern.search(email) is not None
