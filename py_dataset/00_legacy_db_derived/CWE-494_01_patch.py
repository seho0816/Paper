import subprocess
import urllib.parse
import re


class PluginInstaller:
    def install_from_url(self, wheel_url: str) -> None:
        parsed_url = urllib.parse.urlparse(wheel_url)
        
        # Reconstruct URL without the fragment part, as pip expects the hash
        # separately via --hash, not as part of the primary URL argument.
        url_without_fragment = parsed_url._replace(fragment="").geturl()

        pip_args = ["pip", "install", url_without_fragment]
        
        # CWE-494 fix: Check for an integrity hash in the URL fragment.
        # If no hash is provided, the installation must be prevented to avoid
        # downloading code without an integrity check.
        if parsed_url.fragment:
            # Look for common hashing algorithms in the fragment, e.g., #sha256=abcdef...
            # Pip supports sha256, sha384, sha512, sha1, and md5.
            hash_match = re.match(r"(sha256|sha384|sha512|sha1|md5)=(.*)", parsed_url.fragment, re.IGNORECASE)
            if hash_match:
                algorithm = hash_match.group(1).lower()
                hash_value = hash_match.group(2)
                
                # Basic validation for the hash value itself (must be hexadecimal characters).
                # This prevents command injection through malformed hash values.
                if re.fullmatch(r"[0-9a-fA-F]+", hash_value):
                    pip_args.extend(["--hash", f"{algorithm}:{hash_value}"])
                else:
                    # If the hash value is invalid, we cannot perform an integrity check. Fail securely.
                    raise ValueError(
                        f"Invalid hash value '{hash_value}' in URL fragment. "
                        "Expected hexadecimal characters only for integrity hash."
                    )
            else:
                # If a fragment exists but does not match the expected hash format,
                # it's not a valid integrity check. Fail securely.
                raise ValueError(
                    f"URL fragment '{parsed_url.fragment}' is not a recognized integrity hash format. "
                    "Expected format like '#sha256=<hash_value>' for direct URL installations."
                )
        else:
            # CWE-494: No integrity hash provided in the URL fragment.
            # To address this vulnerability, direct URL installations *must* include an integrity hash.
            # Therefore, we raise an error and prevent installation.
            raise ValueError(
                "CWE-494: No integrity hash (e.g., #sha256=...) provided in URL fragment. "
                "Direct URL installations require an integrity check to prevent downloading tampered code."
            )

        subprocess.run(
            pip_args,
            check=True,
        )


def install_requested_plugin(download_url: str) -> None:
    installer = PluginInstaller()
    installer.install_from_url(download_url)
