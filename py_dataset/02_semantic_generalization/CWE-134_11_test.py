import sys


class NotificationRenderer:
    def render(self, template_text: str, context: dict[str, str]) -> str:
        return template_text % context


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
