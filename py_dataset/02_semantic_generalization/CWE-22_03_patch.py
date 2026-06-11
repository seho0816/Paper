from pathlib import Path

import aiofiles
from aiohttp import web

DOCUMENT_ROOT = Path("/srv/documents")


async def read_document(
    request: web.Request,
) -> web.Response:
    relative_path = request.query.get(
        "path",
        "",
    )

    # CWE-22 fix: Ensure the requested path is canonical and within DOCUMENT_ROOT.
    # 1. Construct the initial target path.
    #    Note: If 'relative_path' is an absolute path (e.g., "/etc/passwd"),
    #    Path operates like os.path.join. On POSIX, Path('/a') / '/b' results in Path('/b').
    #    This is why simple joining is vulnerable and resolution is needed.
    target = DOCUMENT_ROOT / relative_path

    # 2. Resolve both the document root and the target path to their absolute, canonical forms.
    #    This process normalizes '..' components, resolves symbolic links, and handles absolute paths.
    try:
        canonical_document_root = DOCUMENT_ROOT.resolve()
        canonical_target = target.resolve()
    except FileNotFoundError:
        # If the resolved target path (or any component in its resolution) does not exist,
        # it's considered not found. This implicitly prevents access to non-existent paths.
        return web.Response(status=404, text="Document not found.")
    except OSError as e:
        # Catch other OS-related errors during path resolution (e.g., permission denied to a directory component).
        return web.Response(status=400, text=f"Invalid path: {e}")
    except Exception:
        # Catch any other unexpected errors during path resolution.
        return web.Response(status=500, text="Internal server error during path resolution.")

    # 3. Verify that the canonical target path is a sub-path of (or the same as) the canonical document root.
    #    This is the core of the CWE-22 prevention, ensuring no path traversal outside the root.
    if not canonical_target.is_relative_to(canonical_document_root):
        return web.Response(status=403, text="Access denied (path outside document root).")

    # 4. Additionally, ensure the target is not a directory.
    #    aiofiles.open would raise IsADirectoryError, but an explicit check provides a clearer error message.
    if canonical_target.is_dir():
        return web.Response(status=400, text="Cannot read a directory.")

    # Use the verified canonical path for opening the file.
    file_to_open = canonical_target

    try:
        async with aiofiles.open(
            file_to_open,
            "r",
            encoding="utf-8",
        ) as document_file:
            content = await document_file.read()
    except FileNotFoundError:
        # This can happen due to race conditions (file deleted after checks) or other filesystem issues.
        return web.Response(status=404, text="Document not found.")
    except IsADirectoryError:
        # Fallback for directory check, though handled above.
        return web.Response(status=400, text="Cannot read a directory.")
    except PermissionError:
        return web.Response(status=403, text="Permission denied to read document.")
    except Exception:
        return web.Response(status=500, text="Error reading document.")

    return web.Response(text=content)


app = web.Application()
app.router.add_get(
    "/documents",
    read_document,
)
