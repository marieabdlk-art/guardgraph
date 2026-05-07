from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginPayload(BaseModel):
    email: str
    password: str


class ResetPayload(BaseModel):
    email: str


@router.post("/login")
def login(payload: LoginPayload):
    return {"token": "demo"}


@router.post("/password-reset")
def password_reset(payload: ResetPayload):
    return {"status": "reset_sent"}
