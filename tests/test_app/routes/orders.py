from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from services.auth import get_current_user

router = APIRouter(prefix="/api/orders", tags=["orders"])


class FakeDB:
    def execute(self, *args, **kwargs):
        return self
    def fetchone(self):
        return {"ok": True, "user_id": 1}
    def fetchall(self):
        return []


db = FakeDB()


class OrderUpdate(BaseModel):
    status: str


# RISK: order_id without ownership check
@router.get("/{order_id}")
def get_order(order_id: int, current_user = Depends(get_current_user)):
    result = db.execute("SELECT * FROM orders WHERE id = ?", order_id)
    return result.fetchone()


# SAFE: auth + ownership check + pydantic validation
@router.patch("/{order_id}")
def update_order(order_id: int, payload: OrderUpdate, current_user = Depends(get_current_user)):
    order = db.execute("SELECT * FROM orders WHERE id = ?", order_id).fetchone()
    if order["user_id"] != current_user.id:
        raise HTTPException(status_code=403)
    db.execute("UPDATE orders SET status = ? WHERE id = ?", payload.status, order_id)
    return {"status": "updated"}


# RISK: raw request json into SQL f-string
@router.post("/search")
async def search_orders(request: Request):
    body = await request.json()
    q = body.get("q", "")
    result = db.execute(f"SELECT * FROM orders WHERE status = '{q}'")
    return result.fetchall()
