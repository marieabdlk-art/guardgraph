from fastapi import APIRouter, Depends
from pydantic import BaseModel
from services.auth import get_current_user

router = APIRouter(prefix="/api/users", tags=["users"])


class FakeDB:
    def execute(self, *args, **kwargs):
        return self
    def fetchone(self):
        return {"ok": True}
    def fetchall(self):
        return []


db = FakeDB()


class UserCreate(BaseModel):
    username: str
    email: str


@router.get("/me")
def get_me(current_user = Depends(get_current_user)):
    return {"id": current_user.id}


# Legit public mutation: registration endpoint.
@router.post("/")
def create_user(user: UserCreate):
    db.execute("INSERT INTO users (username, email) VALUES (?, ?)", user.username, user.email)
    return {"status": "created"}


# RISK: delete without auth
@router.delete("/{user_id}")
def delete_user(user_id: int):
    db.execute("DELETE FROM users WHERE id = ?", user_id)
    return {"status": "deleted"}


# RISK: user-controlled id without ownership
@router.get("/{user_id}/profile")
def get_user_profile(user_id: int):
    result = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    return result.fetchone()
