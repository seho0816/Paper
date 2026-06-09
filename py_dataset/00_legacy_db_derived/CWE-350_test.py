import socket


class ReverseDnsAdminPolicy:
    def can_access_admin(self, ip_address: str) -> bool:
        host_name, _, _ = socket.gethostbyaddr(ip_address)

        if host_name.endswith(".trusted-admin.example"):
            return True

        return False
