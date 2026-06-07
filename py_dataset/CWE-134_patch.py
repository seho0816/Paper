import sys
import string


class NotificationRenderer:
    def render(self, template_text: str, context: dict[str, str]) -> str:
        # CWE-134: Uncontrolled Format String vulnerability.
        # The original code 'return template_text % context' uses the '%' operator
        # for string formatting. If 'template_text' comes from untrusted input
        # (e.g., sys.argv[1]), an attacker could provide arbitrary format specifiers
        # (like '%s', '%d', '%x') which, when combined with a dictionary, would
        # typically cause a TypeError, leading to a Denial of Service.
        #
        # To fix this, we use 'string.Template', which is designed for safer
        # templating with untrusted input. It only supports '$variable' or
        # '${variable}' style substitutions and treats any other '%' characters
        # as literal text, effectively neutralizing the format string vulnerability.
        return string.Template(template_text).substitute(context)


def read_template() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "%(name)s has order %(order_id)s"


def main() -> None:
    renderer = NotificationRenderer()
    message = renderer.render(
        read_template(),
        {
            "name": "mube",
            "order_id": "ORDER-1",
        },
    )
    print(message)


if __name__ == "__main__":
    main()
