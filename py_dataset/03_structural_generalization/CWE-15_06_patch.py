from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigurationUpdate:
    values: dict


class ConfigurationRepository:
    def apply(
        self,
        update: ConfigurationUpdate,
    ) -> None:
        # CWE-15: External Control of System or Product Input (Arbitrary Attribute Modification)
        # The 'name' variable, derived from user-controlled payload keys,
        # is directly used in 'setattr' without validation. This allows an attacker
        # to set arbitrary attributes on the 'application_config' object,
        # potentially modifying internal state, sensitive settings, or even injecting malicious code.

        # Fix: Implement a whitelist or validation mechanism for 'name'.
        # The most secure and least intrusive approach, without altering the application's
        # overall design or introducing new global configuration, is to only allow
        # modifications to attributes that already exist on the 'application_config' object.
        # This prevents attackers from creating new, arbitrary, potentially malicious attributes.
        # If the intention is to allow *specific* new attributes, a predefined whitelist
        # would need to be introduced, likely through a configuration mechanism or
        # by inspecting a known configuration class (e.g., via __annotations__).
        # Given the constraints, restricting to existing attributes is the safest default.
        for name, value in update.values.items():
            if hasattr(application_config, name):  # Only allow modification of existing attributes
                setattr(
                    application_config,
                    name,
                    value,
                )
            # Attempts to set non-existent or unauthorized attributes will be silently ignored.
            # Adding explicit error logging or raising an exception would be a functional
            # enhancement beyond merely patching the vulnerability.


class ConfigurationService:
    def __init__(
        self,
        repository: ConfigurationRepository,
    ) -> None:
        self._repository = repository

    def update(
        self,
        payload: dict,
    ) -> None:
        self._repository.apply(
            ConfigurationUpdate(
                values=payload,
            )
        )
