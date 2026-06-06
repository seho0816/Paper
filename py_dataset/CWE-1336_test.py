import sys
from jinja2 import Template


def read_template_source() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return input("message template: ")


def build_template_context(customer_name: str, amount: int) -> dict:
    return {
        "customer_name": customer_name,
        "amount": amount,
        "company": "ExamplePay",
    }


def render_message_from_user_template() -> str:
    template_source = read_template_source()
    context = build_template_context("mube", 30000)

    template = Template(template_source)
    return template.render(context)


def main() -> None:
    rendered = render_message_from_user_template()
    print(rendered)


if __name__ == "__main__":
    main()