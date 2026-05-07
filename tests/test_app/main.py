from fastapi import FastAPI
from routes import admin, auth, contact, orders, payments, search, users

app = FastAPI()
app.include_router(users.router)
app.include_router(orders.router)
app.include_router(search.router)
app.include_router(payments.router)
app.include_router(admin.router)
app.include_router(auth.router)
app.include_router(contact.router)
