import requests
import urllib.parse
import socket
import ipaddress

from flask import Flask, request, jsonify

app = Flask(__name__)

def is_ip_restricted(ip_address_str):
    """
    Checks if an IP address belongs to a restricted range (private, loopback, reserved, multicast, link-local).
    """
    try:
        ip_addr = ipaddress.ip_address(ip_address_str)
        if ip_addr.is_loopback or \
           ip_addr.is_private or \
           ip_addr.is_reserved or \
           ip_addr.is_multicast or \
           ip_addr.is_link_local:
            return True
        return False
    except ValueError:
        # If ip_address_str is not a valid IP address string, treat it as restricted for safety.
        return True

@app.post("/api/image/fetch")
def fetch_image():
    image_url = request.json.get(
        "url",
        "",
    )

    if not image_url:
        return jsonify({"error": "URL parameter is missing."}), 400

    parsed_url = urllib.parse.urlparse(image_url)

    # 1. Validate URL scheme
    if parsed_url.scheme not in ["http", "https"]:
        return jsonify({"error": "Unsupported URL scheme. Only http and https are allowed."}), 400

    # 2. Ensure hostname exists
    if not parsed_url.hostname:
        return jsonify({"error": "Invalid URL: hostname is missing."}), 400
    
    # 3. Resolve hostname to IP(s) and check for restricted IPs
    try:
        # Resolve the hostname to an IPv4 address.
        # This is generally sufficient for SSRF as attackers usually target a single IP.
        # For more comprehensive checks involving IPv6 or multiple IPs,
        # socket.getaddrinfo could be used, but socket.gethostbyname is simpler for common cases.
        resolved_ip = socket.gethostbyname(parsed_url.hostname)
        if is_ip_restricted(resolved_ip):
            return jsonify({"error": "Access to the specified host is restricted."}), 403
    except socket.gaierror:
        # Hostname could not be resolved (e.g., non-existent domain)
        return jsonify({"error": "Could not resolve hostname."}), 400
    except Exception as e:
        # Catch any other unexpected errors during IP resolution
        return jsonify({"error": f"An unexpected error occurred during hostname resolution: {e}"}), 500

    # If all checks pass, proceed with the request
    try:
        response = requests.get(
            image_url,
            timeout=5,
            allow_redirects=True # Keep redirects enabled but initial target is validated
        )
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request to external service timed out."}), 504 # Gateway Timeout
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Failed to connect to the external service."}), 502 # Bad Gateway
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"HTTP error occurred while fetching image: {e}"}), e.response.status_code if e.response is not None else 500
    except requests.exceptions.RequestException as e:
        # Catch any other request-related errors
        return jsonify({"error": f"Failed to fetch image: {e}"}), 500

    return {
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "size": len(
            response.content,
        ),
    }
