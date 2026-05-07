from fastapi import APIRouter, Depends
from benchmarks.fastapi_di_app.auth import get_current_user

router = APIRouter(prefix="/di/route-level", tags=["di-route-level"])


@router.delete("/items/{item_id}", dependencies=[Depends(get_current_user)])
def delete_item_route_level(item_id: int):
    # Protected by route-level dependency. GuardGraph should NOT report missing auth.
    return {"deleted": item_id}
