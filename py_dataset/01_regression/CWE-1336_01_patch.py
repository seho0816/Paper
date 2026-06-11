from flask import render_template_string, request
from jinja2 import SandboxedEnvironment, select_autoescape


def preview_email():
    source = request.form.get(
        "template",
        "",
    )

    name_var = request.form.get(
        "name",
        "",
    )

    # Use a SandboxedEnvironment to render user-provided templates.
    # This mitigates Server-Side Template Injection (CWE-1336) by restricting
    # access to potentially dangerous functions and attributes within the template context.
    env = SandboxedEnvironment(
        autoescape=select_autoescape(['html', 'xml']),
    )
    template = env.from_string(source)
    return template.render(name=name_var)
