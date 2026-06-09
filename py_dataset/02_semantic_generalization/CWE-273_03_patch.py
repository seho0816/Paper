import os


def render_untrusted_template(template_path: str, renderer_uid: int) -> bytes:
    original_euid = os.geteuid()
    try:
        os.seteuid(renderer_uid)
        return render_template_file(template_path)
    except PermissionError:
        audit_privilege_failure(renderer_uid)
        raise
    finally:
        os.seteuid(original_euid)
