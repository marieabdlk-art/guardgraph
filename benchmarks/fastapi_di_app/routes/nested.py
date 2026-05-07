from fastapi import APIRouter, Depends
from benchmarks.fastapi_di_app.auth import get_current_admin

router = APIRouter(prefix="/di/nested", tags=["di-nested"])


@router.delete("/admin-items/{item_id}")
def delete_admin_item(item_id: int, admin=Depends(get_current_admin)):
    # Protected by nested dependency. GuardGraph should treat this as auth + permission.
    return {"deleted": item_id, "admin": admin.id}
