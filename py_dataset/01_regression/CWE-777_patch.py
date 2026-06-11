import re


def is_allowed_admin_host(hostname: str) -> bool:
    # CWE-777: Polymorphic Typing
    # The vulnerability can arise if the function implicitly handles objects of unexpected types,
    # which might bypass security checks or lead to unexpected behavior if an attacker controls
    # the type of the `hostname` parameter.
    # Although `re.search` itself raises a TypeError for non-string inputs,
    # explicitly validating the type at the function boundary acts as a defensive measure
    # against potential polymorphic type issues, ensuring that 'hostname' is unequivocally a string.
    # This prevents an attacker from passing a malicious object that might leverage
    # dynamic typing for an exploit if the regex engine or subsequent processing were less strict.
    if not isinstance(hostname, str):
        raise TypeError("hostname must be a string")

    pattern = re.compile(r'admin\.example\.com')
    return pattern.search(hostname) is not None
