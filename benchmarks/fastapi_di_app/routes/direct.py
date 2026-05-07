from fastapi import APIRouter, Depends
from benchmarks.fastapi_di_app.auth import get_current_user

router = APIRouter(prefix="/di/direct", tags=["di-direct"])


@router.delete("/items/{item_id}")
def delete_item_direct(item_id: int, current_user=Depends(get_current_user)):
    # Protected by direct dependency. GuardGraph should NOT report missing auth.
    return {"deleted": item_id, "user": current_user.id}


@router.delete("/items-public/{item_id}")
def delete_item_without_dependency(item_id: int):
    # Negative control: no dependency on purpose.
    db_execute = "DELETE FROM items WHERE id = ?"
    return {"query": db_execute, "deleted": item_id}
