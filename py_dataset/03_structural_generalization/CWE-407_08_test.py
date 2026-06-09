from dataclasses import dataclass


@dataclass(frozen=True)
class RecommendationRequest:
    products: list[dict]


class RecommendationService:
    def build_pairs(
        self,
        request: RecommendationRequest,
    ) -> list[tuple[str, str]]:
        pairs = []

        for left in request.products:
            for right in request.products:
                if left["id"] >= right["id"]:
                    continue

                if similarity_score(
                    left,
                    right,
                ) > 0.8:
                    pairs.append(
                        (
                            left["id"],
                            right["id"],
                        )
                    )

        return pairs
