import asyncio
import sys
import httpx
import urllib.parse
import ipaddress
import socket


class LinkPreviewService:
    async def fetch_preview(self, target_url: str) -> str:
        # 1. Parse the URL
        parsed_url = urllib.parse.urlparse(target_url)

        # 2. Validate scheme
        if parsed_url.scheme not in ["http", "https"]:
            print(f"SSRF Blocked: Invalid scheme '{parsed_url.scheme}' for URL '{target_url}'", file=sys.stderr)
            return "Error: Invalid URL scheme. Only HTTP and HTTPS are allowed."

        # 3. Validate hostname exists
        if not parsed_url.hostname:
            print(f"SSRF Blocked: No hostname provided for URL '{target_url}'", file=sys.stderr)
            return "Error: No hostname found in the URL."

        # 4. Resolve hostname to IP addresses and validate them
        try:
            # socket.getaddrinfo returns a list of 5-tuples:
            # (family, socktype, proto, canonname, sockaddr)
            # We are interested in sockaddr[0] which is the IP address string.
            # Use asyncio.to_thread for the blocking socket call to prevent blocking the event loop.
            addr_info = await asyncio.to_thread(
                socket.getaddrinfo,
                parsed_url.hostname,
                parsed_url.port or parsed_url.scheme,  # Default port based on scheme if not specified
                socket.AF_UNSPEC,  # Allow both IPv4 and IPv6
                socket.SOCK_STREAM,  # TCP socket
                socket.IPPROTO_TCP
            )

            # Extract unique IP addresses to avoid redundant checks
            resolved_ips = {sa[0] for family, socktype, proto, canonname, sa in addr_info}

            for ip_str in resolved_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)

                    # Check for private, loopback, and link-local IPs to prevent SSRF
                    # is_private: RFC 1918 (IPv4) and RFC 4193 (IPv6) private ranges
                    # is_loopback: 127.0.0.0/8 (IPv4) and ::1/128 (IPv6)
                    # is_link_local: 169.254.0.0/16 (IPv4) and fe80::/10 (IPv6)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        print(f"SSRF Blocked: Request to internal/forbidden IP '{ip_str}' for host '{parsed_url.hostname}' (URL: '{target_url}')", file=sys.stderr)
                        return "Error: Request to internal or forbidden IP address."

                except ValueError:
                    # Catch cases where ipaddress.ip_address cannot parse an IP string
                    print(f"SSRF Warning: Could not parse IP '{ip_str}' resolved for '{parsed_url.hostname}' (URL: '{target_url}')", file=sys.stderr)
                    continue  # Continue to check other resolved IPs if any

        except socket.gaierror as e:
            # Hostname could not be resolved
            print(f"SSRF Blocked: Could not resolve hostname '{parsed_url.hostname}' (URL: '{target_url}'): {e}", file=sys.stderr)
            return "Error: Could not resolve hostname."
        except Exception as e:
            # Catch any other unexpected errors during IP validation
            print(f"SSRF Blocked: Unexpected error during IP validation for '{parsed_url.hostname}' (URL: '{target_url}'): {e}", file=sys.stderr)
            return "Error: Failed to validate target URL."

        # If all checks pass, proceed with the request
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            try:
                response = await client.get(target_url)
                response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
                return response.text[:500]
            except httpx.RequestError as e:
                # This covers network errors, DNS errors (if not caught by getaddrinfo), etc.
                print(f"HTTP Request Error: Failed to fetch '{target_url}': {e}", file=sys.stderr)
                return f"Error: Failed to fetch content from {target_url}."
            except httpx.HTTPStatusError as e:
                # This covers non-2xx HTTP responses
                print(f"HTTP Status Error: Received {e.response.status_code} from '{target_url}': {e.response.text[:100]}", file=sys.stderr)
                return f"Error: Received HTTP status {e.response.status_code} from {target_url}."
            except Exception as e:
                # Catch any other unexpected errors during the HTTP request
                print(f"Unexpected HTTP Fetch Error for '{target_url}': {e}", file=sys.stderr)
                return "Error: An unexpected error occurred while fetching content."


def read_target_url() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return input("target url: ")


async def main_async() -> None:
    target_url = read_target_url()
    service = LinkPreviewService()
    preview = await service.fetch_preview(target_url)
    print(preview)


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
