from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

import src.tokens as lib
from src.tokens import delete_data

router = APIRouter(
    prefix="/auth",
    tags=["Auth"]
)

async def login_or_register(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> lib.Token:
    if lib.user_exists(form_data.username):
        return await login(form_data)
    return await register(form_data)


@router.post("/sign_up")
async def register(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> lib.Token:
    return await lib.register(form_data)


@router.post("/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> lib.Token:
    return await lib.login_for_access_token(form_data)