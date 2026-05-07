from fastapi import HTTPException


class User:
    def __init__(self, id=1, role="user", is_active=True):
        self.id = id
        self.role = role
        self.is_active = is_active


def get_current_user(token: str = None):
    if token is None:
        raise HTTPException(status_code=401)
    return User(id=1, role="user")


def require_admin(current_user):
    if current_user.role != "admin":
        raise HTTPException(status_code=403)
    return True
