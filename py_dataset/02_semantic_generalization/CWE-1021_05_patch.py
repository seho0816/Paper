from fastapi.responses import HTMLResponse


def render_admin_dashboard(html: str) -> HTMLResponse:
    return HTMLResponse(
        content=html,
        headers={
            'Cache-Control': 'no-store',
            'X-Frame-Options': 'DENY',
        },
    )
