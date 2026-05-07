from typing import Annotated

from fastapi import APIRouter, Depends
from benchmarks.fastapi_di_app.auth import User, get_current_user

router = APIRouter(prefix="/di/annotated", tags=["di-annotated"])


@router.delete("/items/{item_id}")
def delete_item_annotated(
    item_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
):
    # Protected by Annotated dependency. GuardGraph should NOT report missing auth.
    return {"deleted": item_id, "user": current_user.id}
