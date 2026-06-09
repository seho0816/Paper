from starlette.responses import HTMLResponse


def recovery_page(html: str) -> HTMLResponse:
    return HTMLResponse(
        html,
        headers={
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
        },
    )
