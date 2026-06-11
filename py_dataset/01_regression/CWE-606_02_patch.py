MAX_PAGE_COUNT = 1000  # Define a reasonable maximum page count to prevent resource exhaustion

def build_report_pages(payload: dict) -> list[bytes]:
    # Convert 'page_count' to an integer. If conversion fails, a ValueError is raised.
    page_count = int(payload['page_count'])

    # CWE-606 mitigation: Validate the 'page_count' input for the loop condition.
    # Ensure page_count is non-negative and does not exceed a defined maximum.
    # This prevents excessive loop iterations that could lead to a denial-of-service.
    page_count = max(0, min(page_count, MAX_PAGE_COUNT))

    # The original logic for rendering pages is maintained with the now-safe page_count.
    # render_report_page is assumed to be defined elsewhere and handle its inputs safely.
    return [render_report_page(index, payload['template']) for index in range(page_count)]

# The following is a placeholder for `render_report_page` to make the code executable
# if someone were to try it, but it's not part of the required patch.
# In a real scenario, this function would be imported or defined elsewhere.
# As per rules, I will not include this in the final output.
# def render_report_page(index: int, template_name: str) -> bytes:
#    """Placeholder for the actual report rendering function."""
#    return f"Page {index} using template {template_name}".encode('utf-8')
