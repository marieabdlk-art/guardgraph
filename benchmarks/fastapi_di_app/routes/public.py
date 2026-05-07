from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/di/public", tags=["di-public"])


class RegisterPayload(BaseModel):
    email: str
    password: str


@router.post("/register")
def register(payload: RegisterPayload):
    # Legit public action. GuardGraph should not demand AUTH_REQUIRED.
    return {"email": payload.email}
