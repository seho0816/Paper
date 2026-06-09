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
