import string

def render_message(
    template: str,
    values: dict,
) -> str:
    # CWE-134 (Uncontrolled Format String) mitigation:
    # The original code uses the '%' operator directly with a user-controlled 'template' string.
    # This is vulnerable because the template can contain arbitrary format specifiers (e.g., %x, %d, %s)
    # which could lead to information leakage (unexpected data formatting), denial of service (via
    # TypeError or KeyError for malicious specifiers), or unintended behavior.
    #
    # string.Template is a safer alternative from Python's standard library for simple string
    # substitutions. It only supports variable substitutions using '$variable_name' or '${variable_name}'
    # syntax, explicitly avoiding the rich and potentially dangerous formatting capabilities
    # of the '%' operator or str.format() when the template string is untrusted.
    return string.Template(template).substitute(values)
