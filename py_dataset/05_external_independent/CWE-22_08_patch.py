from pathlib import Path

from django.http import FileResponse, HttpRequest, Http404

MEDIA_ROOT = Path("/srv/media")


def download_media(
    request: HttpRequest,
) -> FileResponse:
    relative_name = request.GET.get(
        "object",
        "",
    )

    # Resolve MEDIA_ROOT to its absolute, canonical path for robust comparison
    resolved_media_root = MEDIA_ROOT.resolve()

    # Construct the full path based on user input.
    # pathlib's / operator handles path components, including '..'
    # The vulnerability (CWE-22) is that '..' can escape the intended directory.
    # We must validate the resolved path to prevent this.
    target_path = MEDIA_ROOT / relative_name

    try:
        # Resolve the target path to its absolute, canonical form.
        # This normalizes '..', '.', and symlinks.
        resolved_target_path = target_path.resolve()
    except FileNotFoundError:
        # If the path doesn't exist after resolution, it's a 404.
        # This catches cases where relative_name leads to a non-existent path.
        raise Http404("File not found.")
    except Exception:
        # Catch other potential issues during path resolution (e.g., invalid characters,
        # permission issues to intermediate directories which might prevent resolution).
        raise Http404("Invalid file path or access denied.")

    # CRITICAL SECURITY CHECK (CWE-22 fix):
    # Ensure the resolved target path is strictly within the resolved MEDIA_ROOT.
    # .is_relative_to() checks if a path is a subpath of another, preventing path traversal.
    if not resolved_target_path.is_relative_to(resolved_media_root):
        # If the resolved path is outside MEDIA_ROOT, deny access.
        # Raising Http404 is appropriate as it doesn't leak information about
        # the file system structure outside MEDIA_ROOT, while preventing unauthorized access.
        raise Http404("Access denied or file not found.")

    # If all security checks pass, attempt to open and serve the file.
    try:
        return FileResponse(
            resolved_target_path.open("rb"),
            as_attachment=True,
        )
    except FileNotFoundError:
        # Redundant if FileNotFoundError was already caught by resolve(),
        # but good for robustness if the file was removed between resolve() and open().
        raise Http404("File not found.")
    except PermissionError:
        # If the file exists but access is denied due to OS permissions,
        # treat it as not found or denied for security reasons.
        raise Http404("Access denied or file not found.")
