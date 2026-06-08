from flask import Flask, request, abort
from urllib.parse import urlparse
import http.client
import socket
import ipaddress

app = Flask(__name__)

# Helper function to check if an IP address is private, loopback, or unspecified.
def is_private_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_loopback or        # 127.0.0.0/8, ::1/128
            ip_obj.is_link_local or     # 169.254.0.0/16, fe80::/10
            ip_obj.is_private or        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7
            ip_obj.is_unspecified       # 0.0.0.0, ::
        )
    except ValueError:
        # This should ideally not be hit if IPs come from socket.getaddrinfo
        # as it typically returns valid IP strings.
        return False

@app.route('/pfp')
def pfp():
    url_param = request.args.get('url')
    if not url_param:
        abort(400, "URL parameter 'url' is missing.")

    url = urlparse(url_param)

    # Validate URL scheme to restrict to HTTP, as http.client.HTTPConnection is used.
    # An empty scheme might indicate a relative URL or just a hostname, which is processed below.
    if url.scheme not in ('http', ''):
        abort(400, "Only HTTP scheme is allowed for fetching images.")

    if not url.hostname:
        abort(400, "Invalid URL: hostname is missing.")

    # Resolve hostname to IP addresses and check for private/internal IPs to prevent SSRF (CWE-918).
    try:
        resolved_ips = []
        # If url.port is None, http.client.HTTPConnection defaults to port 80.
        # We use this default for getaddrinfo to consistently mimic connection intent.
        port_to_resolve = url.port if url.port is not None else 80

        # Use socket.getaddrinfo to resolve hostname to all its IP addresses (IPv4 and IPv6).
        # socket.AF_UNSPEC allows resolving both IPv4 and IPv6 addresses.
        addr_info = socket.getaddrinfo(url.hostname, port_to_resolve, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for res in addr_info:
            # res[4] is the sockaddr tuple; for IPv4/IPv6, sockaddr[0] is the IP address string.
            ip_address = res[4][0]
            resolved_ips.append(ip_address)

        # Check if any of the resolved IP addresses are private or internal.
        for ip in resolved_ips:
            if is_private_ip(ip):
                abort(403, "Access to private network resources is forbidden.")

    except socket.gaierror:
        # Hostname resolution failed (e.g., domain does not exist or invalid hostname).
        abort(400, "Could not resolve hostname or invalid hostname.")
    except Exception:
        # Catch any other unexpected errors during IP resolution.
        abort(500, "An unexpected error occurred during hostname resolution.")

    conn = None # Initialize conn outside the try block for finally to work.
    try:
        # Maintain original connection type and port handling as per the vulnerable code.
        # If url.port is None, http.client.HTTPConnection correctly defaults to 80.
        conn = http.client.HTTPConnection(url.hostname, url.port)
        
        # Ensure path is not empty; default to '/' for a valid GET request.
        conn.request('GET', url.path if url.path else '/')
        response = conn.getresponse()

        # Read the response body once and store it.
        # The original code called response.read() twice, which would lead to an empty second read.
        response_data = response.read()

        # The 'user' object is assumed to be available in the surrounding context.
        user.updateProfileImage(response_data)
        
        return response_data

    except http.client.HTTPException:
        # Catch specific HTTP client errors (e.g., protocol errors, bad responses).
        abort(502, "Failed to fetch image from the remote server due to an HTTP protocol error.")
    except ConnectionRefusedError:
        # Catch connection refused errors.
        abort(502, "Connection to the remote server was refused.")
    except TimeoutError:
        # Catch connection timeouts.
        abort(504, "Connection to the remote server timed out.")
    except Exception:
        # Catch any other unexpected errors during the connection or data retrieval process.
        abort(500, "An unexpected error occurred while fetching the image.")
    finally:
        # Ensure the connection is closed.
        if conn:
            conn.close()

if __name__ == '__main__':
    # In a real application, the 'user' object would be properly initialized or imported.
    # For this code snippet to run without a NameError if 'user' isn't provided,
    # one might mock it for testing, but per rules, the original structure is preserved.
    # Example (DO NOT UNCOMMENT FOR SUBMISSION, as it's adding new functionality):
    # class MockUser:
    #     def updateProfileImage(self, image_data):
    #         print(f"MockUser: Profile image updated with {len(image_data)} bytes.")
    # user = MockUser()
    app.run(port=3000)
