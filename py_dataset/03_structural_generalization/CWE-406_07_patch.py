import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class DatagramRequest:
    body: bytes
    client_address: tuple[str, int]


class UdpStatusService:
    def handle(
        self,
        server,
        request: DatagramRequest,
    ) -> None:
        if request.body == b"STATUS":
            # CWE-406: Untrusted Search Path
            # The 'load_full_cluster_status()' function might implicitly use the current
            # working directory or other environment-dependent paths to load resources.
            # If the current working directory can be influenced by an attacker or
            # is otherwise untrusted, this could lead to loading malicious resources
            # (e.g., configuration files, libraries, or executables).
            # To mitigate this, we temporarily change the current working directory
            # to a known trusted location before calling the sensitive function,
            # ensuring that any relative path lookups occur within a secure context.
            # We then restore the original working directory.
            
            original_cwd = os.getcwd()
            try:
                # Use the absolute path of the script's directory as a trusted path.
                # This ensures that any relative paths used by load_full_cluster_status()
                # are resolved within the application's own trusted directory.
                trusted_path = os.path.abspath(os.path.dirname(__file__))
                os.chdir(trusted_path)

                payload = json.dumps(
                    load_full_cluster_status()
                ).encode(
                    "utf-8"
                )
            finally:
                # Always restore the original current working directory to avoid
                # affecting other parts of the application or subsequent requests.
                os.chdir(original_cwd)
            
            server.sendto(
                payload,
                request.client_address,
            )
