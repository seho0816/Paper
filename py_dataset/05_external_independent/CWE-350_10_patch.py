import socket


class OperationsService:
    def Run(
        self,
        request,
        context,
    ):
        peer_ip = extract_peer_ip(
            context.peer()
        )

        # CWE-350: Reliance on Representation of Data instead of Data Itself
        # The original code used the hostname obtained from a reverse DNS lookup (socket.gethostbyaddr)
        # for access control. This is a vulnerability because an attacker can control their own
        # reverse DNS entry to spoof a trusted hostname.
        # To remove this vulnerability, the security decision based on the untrusted
        # hostname has been removed.
        # If specific access control is required, it should be implemented based on
        # the actual 'peer_ip' (e.g., checking against a list of trusted IP addresses or CIDR ranges),
        # not on the result of a reverse DNS lookup.

        return run_operation(
            request.operation
        )
