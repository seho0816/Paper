from jinja2 import Template, SandboxedEnvironment


def send_saved_template(
    template_id: str,
    context: dict,
) -> None:
    source = template_repository.load_source(
        template_id
    )
    # CWE-1336: Improper Neutralization of Special Elements used in a Template Engine
    # If the 'source' string comes from an untrusted origin, it could contain malicious
    # Jinja2 directives, leading to Server-Side Template Injection (SSTI).
    # To mitigate this, a SandboxedEnvironment is used, which restricts access to
    # potentially dangerous attributes and methods in the template execution context.
    # autoescape=True is also enabled to prevent Cross-Site Scripting (XSS) if
    # context values contain untrusted user input that is rendered as HTML.
    env = SandboxedEnvironment(autoescape=True)
    template = env.from_string(source)
    body = template.render(
        context
    )
    send_email_body(
        body
    )
