from fastapi import APIRouter, Depends
from pydantic import BaseModel
from services.auth import get_current_user

router = APIRouter(prefix="/api/pay", tags=["payments"])


class PaymentService:
    def charge(self, amount, card):
        return True
    def refund(self, transaction_id):
        return True


payment_service = PaymentService()


class PaymentPayload(BaseModel):
    amount: int
    card_number: str


# RISK: payment action without auth
@router.post("/process")
def process_payment(payload: PaymentPayload):
    payment_service.charge(payload.amount, payload.card_number)
    return {"status": "processed"}


# RISK: auth exists, but strong permission/role does not
@router.post("/secure-process")
def secure_payment(payload: PaymentPayload, current_user = Depends(get_current_user)):
    payment_service.charge(payload.amount, payload.card_number)
    return {"status": "processed"}


# RISK: refund without auth
@router.post("/refund/{transaction_id}")
def refund_transaction(transaction_id: str):
    payment_service.refund(transaction_id)
    return {"status": "refunded"}
