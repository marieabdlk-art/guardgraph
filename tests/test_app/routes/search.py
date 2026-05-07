from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/search", tags=["search"])


class FakeDB:
    def execute(self, *args, **kwargs):
        return self
    def fetchall(self):
        return []


db = FakeDB()


# RISK: raw body/query to SQL f-string
@router.post("/")
async def search_items(request: Request):
    body = await request.json()
    query = body.get("query", "")
    result = db.execute(f"SELECT * FROM items WHERE name LIKE '%{query}%'")
    return result.fetchall()
