from pathlib import Path
import shutil
import os


CERTIFICATE_ROOT = Path('/etc/application/certificates')


def deploy_partner_certificate(
    uploaded_certificate: str,
) -> Path:
    source = Path(uploaded_certificate)
    target = CERTIFICATE_ROOT / source.name
    shutil.copy2(
        source,
        target,
    )
    # CWE-281: Improper Preservation of Permissions
    # shutil.copy2 preserves the original permissions of the source file.
    # For sensitive files like certificates, it's critical to ensure
    # strict permissions (e.g., owner read/write, no access for others)
    # are enforced on the deployed file, regardless of the source's permissions.
    os.chmod(target, 0o600)
    return target
