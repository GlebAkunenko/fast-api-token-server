from fastapi import FastAPI
from src.router import router

import src.config as config
import requests

app = FastAPI(
    title="Tochka Interesa Token Server"
)

app.include_router(router)

@app.on_event("startup")
async def start_up():
    try:
        requests.post(config.start_request)
    except:
        pass



@app.on_event("shutdown")
def on_shutdown():
    try:
        requests.post(config.stop_request)
    except:
        pass
