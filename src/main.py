from fastapi import FastAPI
from src.router import router

app = FastAPI(
    title="Tochka Interesa Token Server"
)

app.include_router(router)
