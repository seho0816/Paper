import socket


def start_profiler_listener() -> socket.socket:
    listener = socket.socket(
        socket.AF_INET6,
        socket.SOCK_STREAM,
    )
    # CWE-1327 (Incorrect Use of Default Unix Domain Socket Permissions) is about
    # overly permissive access. While this is an IPv6 socket, binding to '::' (all
    # IPv6 interfaces) by default can be similarly overly permissive if the profiler
    # is only intended for local access. Restricting the binding to the IPv6
    # loopback address '::1' ensures it's only accessible from the local machine,
    # aligning with the principle of least privilege for an internal tool.
    listener.bind((
        '::1',
        6060,
    ))
    listener.listen()
    return listener
