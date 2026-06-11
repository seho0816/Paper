from flask import Flask, jsonify, request
from urllib.parse import urlparse

app = Flask(__name__)

TRUSTED_ORIGINS = {
    "https://account.example.com",
    "https://support.example.com",
}

def canonicalize_origin(origin_str):
    """
    Canonicalizes an origin string to a standard format (scheme://host:port),
    removing default ports (80 for http, 443 for https) and lowercasing.
    This helps prevent subtle bypasses or accidental rejections due to
    variations in how origin headers might be sent or interpreted.
    """
    if not origin_str:
        return ""
    
    # Handle 'null' origin explicitly as it's a special case and not a standard URL
    if origin_str == "null":
        return "null"

    try:
        parsed = urlparse(origin_str)
        # Scheme and hostname should be lowercased for canonical comparison
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        
        # Reconstruct the origin string
        canonical_parts = [scheme, "://", hostname]
        
        # Only include port if it's non-default for the given scheme
        if port and ((scheme == "http" and port != 80) or \
                     (scheme == "https" and port != 443)):
            canonical_parts.append(f":{port}")
            
        return "".join(canonical_parts)
    except Exception:
        # If parsing fails (e.g., malformed origin), treat it as an invalid/unknown origin
        return ""


@app.get("/api/account/preferences")
def get_account_preferences():
    origin = request.headers.get("Origin", "")
    
    # Canonicalize the incoming origin header before checking against TRUSTED_ORIGINS.
    # This ensures consistent comparison and mitigates CWE-942 by preventing
    # variations in origin string representation from leading to a permissive policy
    # or unexpected rejections.
    canonical_origin = canonicalize_origin(origin)

    response = jsonify({
        "language": "ko",
        "timezone": "Asia/Seoul",
    })

    if canonical_origin in TRUSTED_ORIGINS:
        # Use the canonical form for setting the Access-Control-Allow-Origin header as well.
        # This ensures that the echoed origin is always well-formed and consistent.
        response.headers["Access-Control-Allow-Origin"] = canonical_origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"

    return response
