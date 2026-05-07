from fastapi import APIRouter, Depends
from benchmarks.fastapi_di_app.auth import get_current_user

router = APIRouter(
    prefix="/di/router-level",
    tags=["di-router-level"],
    dependencies=[Depends(get_current_user)],
)


@router.delete("/items/{item_id}")
def delete_item_router_level(item_id: int):
    # Protected by router-level dependency. GuardGraph should NOT report missing auth.
    return {"deleted": item_id}
