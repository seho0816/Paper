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

        # Define a whitelist of attributes that are allowed to be updated.
        # This prevents an attacker from using arbitrary keys in 'values'
        # to modify internal or sensitive attributes of the PluginPolicy object
        # that were not intended for external modification.
        ALLOWED_POLICY_ATTRIBUTES = {
            'enabled',
            'require_signature',
            'sandboxed',
        }

        for key, value in values.items():
            # Only update attributes that are explicitly allowed in the whitelist.
            if key in ALLOWED_POLICY_ATTRIBUTES:
                setattr(
                    policy,
                    key,
                    value,
                )
            # Keys not in ALLOWED_POLICY_ATTRIBUTES will be ignored,
            # preventing unauthorized modification of object state.

        return policy
