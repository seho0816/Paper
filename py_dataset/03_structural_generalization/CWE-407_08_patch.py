from dataclasses import dataclass


@dataclass(frozen=True)
class RecommendationRequest:
    products: list[dict]


class RecommendationService:
    _MAX_PRODUCTS_LIMIT = 1000

    def build_pairs(
        self,
        request: RecommendationRequest,
    ) -> list[tuple[str, str]]:
        if len(request.products) > self._MAX_PRODUCTS_LIMIT:
            raise ValueError(
                f"Too many products in the request. Max allowed: {self._MAX_PRODUCTS_LIMIT}"
            )

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
