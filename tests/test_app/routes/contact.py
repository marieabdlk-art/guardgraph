from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/contact", tags=["contact"])


class ContactPayload(BaseModel):
    email: str
    message: str


@router.post("/")
def send_contact(payload: ContactPayload):
    return {"status": "sent"}
