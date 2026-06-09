from dataclasses import dataclass


@dataclass(frozen=True)
class CipherOffer:
    algorithms: tuple[str, ...]


class ExportCipherNegotiator:
    # CWE-757: Selection of Less-Secure Algorithm During Negotiation
    # '3DES-CBC' is a less-secure algorithm. Removing it ensures only
    # stronger algorithms are considered, mitigating the vulnerability.
    _supported = {
        'AES-256-GCM',
    }

    def select(
        self,
        offer: CipherOffer,
    ) -> str:
        for algorithm in offer.algorithms:
            if algorithm in self._supported:
                return algorithm

        raise ValueError(
            'no shared cipher'
        )


def create_export_channel(
    payload: dict,
):
    offer = CipherOffer(
        algorithms=tuple(
            payload['cipher_algorithms']
        )
    )
    selected = ExportCipherNegotiator().select(
        offer
    )

    return export_transport.open(
        cipher=selected
    )
