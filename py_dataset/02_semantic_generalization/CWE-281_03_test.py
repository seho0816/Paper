from pathlib import Path
import shutil


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
    return target
