from dataclasses import dataclass


@dataclass
class PluginPolicy:
    enabled: bool = True
    require_signature: bool = True
    sandboxed: bool = True


class PluginPolicyStore:
    def __init__(self) -> None:
        self._policies: dict[str, PluginPolicy] = {}

    def update(
        self,
        plugin_id: str,
        values: dict,
    ) -> PluginPolicy:
        policy = self._policies.setdefault(
            plugin_id,
            PluginPolicy(),
        )

        for key, value in values.items():
            setattr(
                policy,
                key,
                value,
            )

        return policy
