import os


def render_untrusted_template(template_path: str, renderer_uid: int) -> bytes:
    try:
        os.seteuid(renderer_uid)
    except PermissionError:
        audit_privilege_failure(renderer_uid)

    return render_template_file(template_path)
