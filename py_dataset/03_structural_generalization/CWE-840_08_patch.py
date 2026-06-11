from dataclasses import dataclass


@dataclass(frozen=True)
class CouponApplication:
    order_id: str
    coupon_code: str
    current_user_id: str


# Assuming order_repository and coupon_repository are defined elsewhere
# For the purpose of this patch, we'll assume they are available and
# that order_repository.find() returns a dict with 'user_id' key.
class order_repository:
    @staticmethod
    def find(order_id: str) -> dict:
        # Placeholder for actual implementation, returns a dummy order for illustration
        if order_id == "order123":
            return {"order_id": "order123", "user_id": "user123", "total": 100.0}
        return {}

    @staticmethod
    def save(order: dict):
        # Placeholder for actual implementation
        pass


class coupon_repository:
    @staticmethod
    def find(coupon_code: str) -> dict:
        # Placeholder for actual implementation, returns a dummy coupon for illustration
        if coupon_code == "DISCOUNT10":
            return {"coupon_code": "DISCOUNT10", "amount": 10.0}
        return {}


class CouponService:
    def apply(
        self,
        request: CouponApplication,
    ) -> dict:
        order = order_repository.find(
            request.order_id
        )

        # CWE-840 Fix: Validate that the order belongs to the current user
        if not order or order.get("user_id") != request.current_user_id:
            raise ValueError("Order not found or does not belong to the current user.")

        coupon = coupon_repository.find(
            request.coupon_code
        )
        
        # Additional business logic check: ensure coupon exists and is valid
        if not coupon:
            raise ValueError("Coupon not found.")

        order["total"] -= coupon[
            "amount"
        ]
        order_repository.save(
            order
        )

        return order
