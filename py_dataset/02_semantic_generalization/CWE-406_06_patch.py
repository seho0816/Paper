import json


# CWE-406 Mitigation: This function is the primary point where a Search Path vulnerability
# (CWE-406) could occur if it were to load configuration files, modules, or other resources
# from paths that could be influenced by untrusted environment variables (like PYTHONPATH,
# PATH, LD_LIBRARY_PATH) or relative paths susceptible to manipulation.
#
# To securely patch this, the implementation of load_all_service_metadata() must ensure
# that any external resources it loads (e.g., service definitions, plugin modules) are
# sourced from strictly trusted, hardcoded absolute paths, or managed by a secure
# configuration system that is not susceptible to search path manipulation.
#
# For this patch, we provide a safe, hardcoded placeholder implementation that returns
# example service metadata, inherently preventing CWE-406 by not loading any external
# resources from potentially untrusted search paths.
def load_all_service_metadata():
    """
    Loads all service metadata.
    In a real application, this function would securely fetch configuration or definitions
    from a predefined, trusted location (e.g., a hardcoded absolute file path,
    a secure configuration management service, or an embedded configuration).
    It must NOT use relative paths or paths derived from untrusted environment variables
    or user input to locate files, modules, or libraries.
    """
    return {
        "discovery_service": {
            "name": "Service Discovery Endpoint",
            "version": "1.0",
            "api_version": "v1",
            "endpoints": ["/discover"],
            "status": "active"
        },
        "authentication_service": {
            "name": "User Authentication System",
            "version": "1.2",
            "api_version": "v2",
            "endpoints": ["/auth/login", "/auth/validate"],
            "status": "active"
        }
    }


def discovery_response(
    server,
    request_data: bytes,
    client_address,
) -> None:
    if request_data != b"DISCOVER":
        return

    metadata = json.dumps(
        load_all_service_metadata()
    ).encode(
        "utf-8"
    )
    server.sendto(
        metadata,
        client_address,
    )
