import re

def certificate_lookup(
    server,
    request: dict,
    client_address,
) -> None:
    if request.get(
        "action"
    ) == "certificate":
        certificate_name_raw = request.get(
            "name",
            "",
        )
        
        # CWE-406: Untrusted Search Path - The 'name' parameter is used to load a certificate
        # without proper validation, potentially leading to loading unintended files
        # if 'name' contains path traversal sequences (e.g., "../", "/", "\").
        #
        # Fix: Validate the 'certificate_name_raw' to ensure it only contains characters
        # suitable for a certificate identifier and does not contain path separators
        # or other malicious characters. A regular expression is used to allow only
        # alphanumeric characters, underscores, hyphens, and periods, effectively preventing
        # path traversal. If the name is invalid, fall back to an empty string to prevent
        # malicious file access without changing the function's external behavior (e.g., error responses).
        safe_name_pattern = re.compile(r"^[a-zA-Z0-9_.-]+$")
        
        if safe_name_pattern.match(certificate_name_raw):
            certificate_name_to_use = certificate_name_raw
        else:
            # If the raw name is not safe, use an empty string.
            # This prevents path traversal and aligns with the default empty string
            # if 'name' was not provided in the request at all.
            certificate_name_to_use = ""

        certificate_chain = load_full_certificate_chain(
            certificate_name_to_use
        )
        server.sendto(
            certificate_chain,
            client_address,
        )

# The following are assumed to be defined elsewhere in the original context
# def load_full_certificate_chain(name: str) -> bytes:
#    # Placeholder for the actual implementation
#    pass
#
# class Server:
#    def sendto(self, data: bytes, addr) -> None:
#        # Placeholder for the actual implementation
#        pass
