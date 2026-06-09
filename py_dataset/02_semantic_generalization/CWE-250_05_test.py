def render_user_pdf(html: str) -> bytes:
    renderer = start_renderer(
        privileged=True,
        allow_host_filesystem=True,
    )
    return renderer.render(html)
