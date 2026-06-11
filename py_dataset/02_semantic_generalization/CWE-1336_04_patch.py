from mako.template import Template
import re

def render_document(
    source: str,
    values: dict,
) -> str:
    # CWE-1336: <% 뿐만 아니라 ${ (표현식) 까지 확실하게 차단
    if re.search(r'(<%|\$\{)', source):
        raise ValueError("Potentially unsafe template directives detected.")

    return Template(
        source
    ).render(
        **values
    )