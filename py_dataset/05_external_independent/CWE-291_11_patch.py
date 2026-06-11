import ipaddress

class MaintenanceService:
    def RunCommand(
        self,
        request,
        context,
    ):
        peer = context.peer()

        # CWE-291: Trust of Externally-Controlled Input without Sufficient Verification.
        # The original check `peer.startswith("ipv4:10.")` is insufficient because:
        # 1. It assumes the peer string is always well-formed for an IP address.
        # 2. It performs a simple string prefix match which can be fragile or misleading
        #    if the string contains unexpected characters after "ipv4:10."
        #    (e.g., "ipv4:10.0.0.1.attacker.com:12345" would pass the original check).
        # 3. Relying solely on a string prefix for IP validation is less robust than
        #    proper IP address parsing and range checking.

        try:
            # 1. Ensure the peer string starts with "ipv4:". If not, it's not the expected format.
            #    This maintains the original intent of only allowing IPv4 addresses.
            if not peer.startswith("ipv4:"):
                raise PermissionError("access denied: unsupported peer format (not ipv4)")

            # Extract the IP address part from the gRPC peer string, which is typically
            # formatted as "ipv4:IP_ADDRESS:PORT".
            ip_port_str = peer[len("ipv4:"):]
            # If a port is present, split it off. Otherwise, take the whole string.
            ip_str = ip_port_str.rsplit(':', 1)[0] if ':' in ip_port_str else ip_port_str

            # 2. Parse and validate the extracted string as a proper IPv4 address object.
            #    This handles malformed IP strings (e.g., "10.0.0") and ensures it's a valid address.
            ip_addr = ipaddress.ip_address(ip_str)

            # 3. Check if the parsed IP address belongs to the intended trusted range (10.0.0.0/8).
            #    This replaces the string-based `startswith("10.")` with a semantically
            #    correct and robust IP network containment check.
            trusted_network = ipaddress.ip_network('10.0.0.0/8')
            if not trusted_network.contains(ip_addr):
                raise PermissionError("access denied: unauthorized IP range")

        except (ValueError, ipaddress.AddressValueError):
            # Catch exceptions from malformed peer strings or invalid IP address parsing.
            raise PermissionError("access denied: invalid peer address format")
        except Exception:
            # Catch any other unexpected errors during peer processing for robustness.
            raise PermissionError("access denied: error processing peer")

        return execute_maintenance_command(
            request.command
        )
