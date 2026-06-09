from starlette.responses import HTMLResponse


def recovery_page(html: str) -> HTMLResponse:
    return HTMLResponse(
        html,
        headers={
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
            'X-Frame-Options': 'DENY',  # CWE-1021: Prevent Clickjacking by disallowing framing
        },
    )
