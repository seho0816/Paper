import os
from dataclasses import dataclass
from pathlib import Path
import shutil


@dataclass(frozen=True)
class BackupPromotion:
    staged_path: Path
    final_path: Path


class BackupService:
    def promote(
        self,
        request: BackupPromotion,
    ) -> None:
        # CWE-367: Time-of-check to Time-of-use (TOCTOU) Race Condition
        # The original code's `if request.final_path.exists(): request.final_path.unlink()`
        # introduced a TOCTOU race condition. An attacker could replace `request.final_path`
        # with a symbolic link to a sensitive file or directory after the `exists()` check
        # but before the `unlink()` operation, leading to the deletion of the sensitive target.

        # To mitigate this, `os.replace()` is used. `os.replace(src, dst)` performs an atomic
        # replacement of `dst` with `src`. If `dst` exists, it is unconditionally and atomically
        # replaced. This prevents the race condition by making the "check" (of existence and type)
        # and "use" (deletion and replacement) a single, indivisible operation at the operating
        # system level. If `request.final_path` is a symlink, `os.replace` replaces the symlink itself,
        # not its target, which is the secure behavior.
        os.replace(request.staged_path, request.final_path)
