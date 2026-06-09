import markdown
import bleach

from flask import request


def render_post():
    submitted_markdown = request.form.get("content", "")
    rendered = markdown.markdown(
        submitted_markdown,
        extensions=["extra"],
    )

    # Sanitize the HTML output from markdown to prevent XSS.
    # bleach.clean removes potentially malicious tags and attributes,
    # allowing only a safe subset of HTML tags and attributes as defined by bleach's defaults.
    # We explicitly provide allowed_tags and allowed_attributes to ensure
    # that common markdown-generated elements are preserved while harmful ones are removed.
    # Using bleach.sanitizer.ALLOWED_TAGS and ALLOWED_ATTRIBUTES provides a robust default set.
    cleaned_rendered = bleach.clean(
        rendered,
        tags=bleach.sanitizer.ALLOWED_TAGS,
        attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES,
        strip=True  # Removes disallowed tags and their content
    )

    return "<main>" + cleaned_rendered + "</main>"
