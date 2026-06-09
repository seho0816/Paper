from mako.template import Template


def render_account_banner(display_name: str) -> str:
    template = Template(
        "<div class='banner'>${display_name}</div>"
    )

    return template.render(
        display_name=display_name,
    )
