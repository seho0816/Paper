def build_report_pages(payload: dict) -> list[bytes]:
    page_count = int(payload['page_count'])
    return [render_report_page(index, payload['template']) for index in range(page_count)]
