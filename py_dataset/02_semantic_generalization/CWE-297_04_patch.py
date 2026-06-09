import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
import ssl


def _cert_to_ssl_dict(cert: x509.Certificate) -> dict:
    """Converts a cryptography x509.Certificate object to the dictionary format expected by ssl.match_hostname."""
    cert_dict = {}

    # Populate 'subject' field
    subject_parts = []
    for attribute in cert.subject:
        # attribute.oid._name provides the string name (e.g., 'commonName', 'countryName')
        subject_parts.append(((attribute.oid._name, attribute.value),))
    cert_dict['subject'] = tuple(subject_parts)

    # Populate 'subjectAltName' field
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_values = []
        for general_name in san_ext.value.general_names:
            if isinstance(general_name, x509.DNSName):
                san_values.append(('DNS', general_name.value))
            elif isinstance(general_name, x509.IPAddress):
                san_values.append(('IP Address', str(general_name.value)))
            # Other GeneralName types can be added if needed (e.g., URI, DirectoryName)
        if san_values:
            cert_dict['subjectAltName'] = tuple(san_values)
    except x509.extensions.ExtensionNotFound:
        # If no SAN extension, this field will be absent, which ssl.match_hostname handles correctly
        pass

    return cert_dict


def verify_peer(
    certificate_der: bytes,
    expected_fingerprint: str,
    requested_host: str,
) -> bool:
    actual_fingerprint = hashlib.sha256(
        certificate_der
    ).hexdigest()

    # First, verify the certificate fingerprint
    if actual_fingerprint != expected_fingerprint:
        return False

    # Second, add host validation to address CWE-297 (Improper Validation of Certificate with Host Mismatch)
    try:
        # Parse the DER certificate using cryptography
        cert_crypto = x509.load_der_x509_certificate(certificate_der, default_backend())
        
        # Convert the cryptography certificate object to the dictionary format expected by ssl.match_hostname
        cert_ssl_dict = _cert_to_ssl_dict(cert_crypto)
        
        # Use ssl.match_hostname for robust hostname validation against the certificate
        # This function raises ssl.CertificateError on mismatch
        ssl.match_hostname(cert_ssl_dict, requested_host)
        
        # If both fingerprint matches and hostname validation succeeds, return True
        return True
    except ssl.CertificateError:
        # Hostname mismatch or other certificate validation error by ssl.match_hostname
        return False
    except Exception:
        # Catch any other potential errors during certificate parsing or conversion
        # In a real application, this error should be logged for investigation.
        return False
