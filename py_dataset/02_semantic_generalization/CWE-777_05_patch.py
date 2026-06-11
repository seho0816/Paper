def can_publish_package(namespace: str) -> bool:
    return "trusted-team" in namespace
