import requests
from urllib.parse import urlparse, urlunparse


def forward_internal_request(
    requested_path: str,
    body: dict,
) -> dict:
    parsed_input_path = urlparse(requested_path)

    # CWE-441: Unintended Proxy/Redirection to an Unregistered Host
    # This vulnerability occurs when `requested_path` contains an absolute URL (with scheme and/or netloc)
    # causing the `requests` library to send the request to an external, unintended host,
    # instead of appending the path to "http://internal-admin".
    #
    # The fix is to ensure that only the path, parameters, query, and fragment components
    # of `requested_path` are used, stripping any scheme or network location (host) information.
    # Additionally, ensure the path component starts with a '/' for consistent URL construction
    # with the base "http://internal-admin".
    if parsed_input_path.scheme or parsed_input_path.netloc:
        # If scheme or netloc are present, it's an attempt to specify an external host.
        # Reconstruct the path part, ignoring scheme and netloc.
        # Ensure the path starts with a '/' if it doesn't already, for proper URL concatenation.
        path_component = parsed_input_path.path
        if not path_component.startswith('/'):
            path_component = '/' + path_component
        
        # urlunparse expects a 6-tuple: (scheme, netloc, path, params, query, fragment)
        # By setting scheme and netloc to empty, we ensure they are not used.
        sanitized_path = urlunparse(('', '', path_component, parsed_input_path.params, parsed_input_path.query, parsed_input_path.fragment))
    else:
        # If no scheme or netloc, it's already a relative path or just a path component.
        # Ensure it starts with a '/' for consistent URL construction,
        # unless it's an empty string, in which case it should remain empty.
        if not requested_path.startswith('/'):
            if requested_path: # Avoid prepending '/' if requested_path is empty
                sanitized_path = '/' + requested_path
            else:
                sanitized_path = requested_path
        else:
            sanitized_path = requested_path

    response = requests.post(
        (
            "http://internal-admin"
            + sanitized_path
        ),
        headers={
            "X-Service-Role": "administrator",
        },
        json=body,
        timeout=5,
    )

    return response.json()
