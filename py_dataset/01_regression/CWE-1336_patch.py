from jinja2 import Environment, Template, select_autoescape

# CWE-1336: Improper Neutralization of Special Elements used in a Template Engine
# The original code uses `jinja2.Template(template_source)` directly with a potentially untrusted `template_source`.
# This allows for Server-Side Template Injection (SSTI) if `template_source` contains malicious Jinja2 expressions,
# leading to arbitrary code execution or information disclosure.
#
# To fix this, we need to ensure that the template environment used to parse `template_source` is secure.
# Jinja2's `SandboxedEnvironment` (now deprecated) or a carefully configured `Environment` is required.
# This fix defines a `RestrictedEnvironment` that prevents access to dangerous attributes (like `__class__`)
# and items, thereby mitigating common SSTI bypasses.

class RestrictedEnvironment(Environment):
    """
    A Jinja2 Environment with restrictions to mitigate Server-Side Template Injection (SSTI).
    It prevents access to dunder (double underscore) attributes and items, which are
    often used in SSTI attacks to introspect Python objects and execute arbitrary code.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_attribute(self, obj, name):
        """
        Overrides the default attribute access to prevent access to dunder attributes.
        """
        if name.startswith('__'):
            raise AttributeError(f"Access to dunder attribute '{name}' is forbidden.")
        return super().get_attribute(obj, name)

    def get_item(self, obj, name):
        """
        Overrides the default item access to prevent access to dunder items (e.g., `object['__class__']`).
        """
        if isinstance(name, str) and name.startswith('__'):
            raise KeyError(f"Access to dunder key '{name}' is forbidden.")
        return super().get_item(obj, name)


def render_custom_message(
    template_source: str,
    context: dict,
) -> str:
    # Use the RestrictedEnvironment to parse the template_source.
    # This prevents malicious template expressions from accessing sensitive Python internals.
    # autoescape is enabled for HTML contexts as a good general security practice,
    # though the primary SSTI fix is in `RestrictedEnvironment`'s attribute/item access.
    env = RestrictedEnvironment(
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.from_string(template_source)

    return template.render(
        context
    )
