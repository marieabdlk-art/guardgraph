from fastapi import Depends


class User:
    def __init__(self, user_id: int = 1, role: str = "user"):
        self.id = user_id
        self.role = role
        self.is_admin = role == "admin"


def get_current_user():
    return User()


def get_current_admin(current_user=Depends(get_current_user)):
    if not current_user.is_admin:
        raise PermissionError("admin required")
    return current_user
