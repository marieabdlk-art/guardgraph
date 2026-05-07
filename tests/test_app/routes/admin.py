from fastapi import APIRouter, Depends
from pydantic import BaseModel
from services.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])


class FakeDB:
    def execute(self, *args, **kwargs):
        return self


db = FakeDB()


class SettingsPayload(BaseModel):
    site_name: str


# RISK: admin operation with auth but no admin role
@router.put("/settings")
def update_settings(payload: SettingsPayload, current_user = Depends(get_current_user)):
    db.execute("UPDATE settings SET site_name = ?", payload.site_name)
    return {"status": "updated"}


# SAFE: admin role check
@router.delete("/users/{user_id}")
def admin_delete_user(user_id: int, current_user = Depends(get_current_user)):
    require_admin(current_user)
    db.execute("DELETE FROM users WHERE id = ?", user_id)
    return {"status": "deleted"}
