import socket


class ReverseDnsAdminPolicy:
    def can_access_admin(self, ip_address: str) -> bool:
        try:
            # 1. Perform reverse DNS lookup to get the hostname.
            host_name, _, _ = socket.gethostbyaddr(ip_address)

            # 2. Check if the obtained hostname matches the trusted pattern.
            if host_name.endswith(".trusted-admin.example"):
                # 3. To mitigate CWE-350 (Reliance on Reverse DNS Resolution for Authorization),
                # perform a forward DNS lookup on the hostname obtained in step 1.
                # This confirms that the hostname genuinely maps back to the original IP address.
                _, _, ip_addresses = socket.gethostbyname_ex(host_name)

                # 4. Verify that the original IP address is among the addresses returned by the
                # forward lookup for the hostname. If it is, the reverse DNS entry is confirmed.
                if ip_address in ip_addresses:
                    return True

            return False
        except (socket.herror, socket.gaierror, socket.error):
            # If any DNS resolution error occurs (e.g., host not found, temporary server error,
            # or malformed IP), deny access by default to maintain a secure posture.
            return False
