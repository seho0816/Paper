import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PartnerBundle:
    source_name: str
    content: bytes


class BundleImporter:
    def import_bundle(
        self,
        bundle: PartnerBundle,
    ) -> int:
        # CWE-353 fix: Missing a Step in an Authentication Scheme.
        # The 'source_name' in PartnerBundle suggests that the source should be verified
        # or authorized before processing its content. This step was missing.
        #
        # A simple check is added here to ensure the source is among a list of
        # authorized sources configured via an environment variable.
        # This prevents processing bundles from unauthenticated or unauthorized sources.

        authorized_sources_str = os.environ.get("AUTHORIZED_BUNDLE_SOURCES", "")
        # Parse authorized sources from a comma-separated string, stripping whitespace.
        # If the environment variable is empty or not set, authorized_sources will be an empty set,
        # ensuring no sources are implicitly authorized by default (secure-by-default).
        authorized_sources = {s.strip() for s in authorized_sources_str.split(',') if s.strip()}

        if not bundle.source_name or bundle.source_name not in authorized_sources:
            # Raise an appropriate exception to indicate an unauthorized or invalid source.
            raise PermissionError(f"Unauthorized or invalid partner bundle source: {bundle.source_name}")

        records = decode_partner_bundle(
            bundle.content
        )

        for record in records:
            partner_repository.save(
                record
            )

        return len(
            records
        )
