def render_user_pdf(html: str) -> bytes:
    renderer = start_renderer(
        privileged=False,
        allow_host_filesystem=False,
    )
    return renderer.render(html)
