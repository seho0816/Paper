import tempfile
from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class RenderResult:
    content: bytes
    extension: str


class TemporaryRenderRepository:
    def save(
        self,
        result: RenderResult,
    ) -> Path:
        # CWE-377 fix: Replaced tempfile.mktemp() with tempfile.mkstemp().
        # mktemp() is insecure due to race conditions as it only generates a name
        # but doesn't create the file. mkstemp() securely creates and opens the
        # file, returning a file descriptor and the path.
        fd, temp_filepath = tempfile.mkstemp(
            prefix="render_",
            suffix=result.extension,
        )
        
        # Convert the string path returned by mkstemp to a Path object.
        path = Path(temp_filepath)

        # Write the content to the file using the file descriptor obtained from mkstemp.
        # The 'with' statement ensures the file descriptor 'fd' is properly closed
        # when the file object 'f' is closed (by default, os.fdopen closes the fd).
        with os.fdopen(fd, 'wb') as f:
            f.write(result.content)

        return path
