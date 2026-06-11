from flask import request


ADMIN_NETWORKS = {
    "127.0.0.1",
    "10.20.30.40",
}


def admin_dashboard():
    # CWE-291: Trust Boundary Violation
    # The original code directly uses `request.remote_addr`, which represents the IP address
    # of the direct client connecting to the Flask application. If the application is
    # deployed behind a reverse proxy (e.g., Nginx, a load balancer), `request.remote_addr`
    # will be the proxy's IP, not the actual end-user client's IP. This can lead to
    # incorrect access control decisions, either denying legitimate users or allowing
    # unauthorized access if the proxy's IP is mistakenly whitelisted.
    #
    # To fix this, we should attempt to get the original client's IP address, which is
    # typically found in the 'X-Forwarded-For' HTTP header set by the reverse proxy.
    # We retrieve the leftmost IP in 'X-Forwarded-For' as it represents the original client.
    # If 'X-Forwarded-For' is not present, we fall back to `request.remote_addr`,
    # assuming a direct connection or an environment without proper proxy configuration.
    #
    # Note: For robust handling of X-Forwarded-For and other proxy headers in Flask,
    # the `werkzeug.middleware.proxy_fix.ProxyFix` middleware is generally recommended.
    # However, given the strict rule to only modify the vulnerable part within the function
    # body without altering the application's overall structure or configuration,
    # this manual parsing within the function is applied as the most direct fix for CWE-291
    # within the given constraints.
    
    client_ip_header = request.headers.get('X-Forwarded-For')
    if client_ip_header:
        # X-Forwarded-For can be a comma-separated list of IPs.
        # The leftmost IP is generally the original client's IP.
        client_ip = client_ip_header.split(',')[0].strip()
    else:
        # If X-Forwarded-For is not present, use the direct caller's IP
        client_ip = request.remote_addr

    if client_ip not in ADMIN_NETWORKS:
        raise PermissionError(
            "access denied"
        )

    return load_admin_dashboard()
