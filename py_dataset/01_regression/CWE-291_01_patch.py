import ipaddress

def operator_access(
    remote_addr: str,
) -> bool:
    candidate_ip = remote_addr.rsplit(',', 1)[-1].strip()

    try:
        ip_obj = ipaddress.ip_address(candidate_ip)
    except ValueError:
        return False
    
    private_network_10 = ipaddress.ip_network("10.0.0.0/8")
    
    return ip_obj in private_network_10
