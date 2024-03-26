from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import src.config as config

import mysql.connector


def create_connection():
    return mysql.connector.connect(
      host=config.host,
      user=config.user,
      password=config.password,
      database=config.database_name
    )


class MyBaseModel(BaseModel):
    @classmethod
    def from_tuple(cls, tpl):
        return cls(**{k: v for k, v in zip(cls.model_fields.keys(), tpl)})


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None


class User(MyBaseModel):
    email: str
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

router = APIRouter()


def _verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def _get_password_hash(password):
    return pwd_context.hash(password)


def _get_user(email: str) -> User | None:
    with create_connection() as db, db.cursor() as cursor:
        cursor.execute(
        f"""
        select users.email, users.hashed_password from ti_token_server.users
        where email = "{email}"
        """)
        result = cursor.fetchall()
        if len(result) == 0:
            return
        return User.from_tuple(result[0])



def _add_user(email, password) -> User:
    password = _get_password_hash(password)
    with create_connection() as db, db.cursor() as cursor:
        cursor.execute(
            f"""
            insert into ti_token_server.users (email, hashed_password) value ("{email}", "{password}");
            """)
        db.commit()
    return User(email=email, hashed_password=password)


def _authenticate_user(email: str, password: str) -> User | None:
    user = _get_user(email)
    if not user:
        return
    if not _verify_password(password, user.hashed_password):
        return
    return user


def _create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    to_encode.update({"ver": config.version})
    encoded_jwt = jwt.encode(to_encode, config.secret_key, algorithm=config.algorithm)
    return encoded_jwt


async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = _authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = _create_access_token(
        data={"sub": user.email}, expires_delta=config.token_lifetime
    )
    return Token(access_token=access_token, token_type="bearer")


def user_exists(email: str) -> bool:
    return _get_user(email) is not None


async def register(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    email, password = form_data.username, form_data.password
    if user_exists(email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with the same email already exists",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = _add_user(email, password)
    access_token = _create_access_token(
        data={"sub": user.email}, expires_delta=config.token_lifetime
    )
    return Token(access_token=access_token, token_type="bearer")


def get_email(token: Annotated[str, Depends(oauth2_scheme)]) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.secret_key, algorithms=[config.algorithm])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = _get_user(token_data.email)
    if user is None:
        raise credentials_exception
    return user.email


async def delete_data(email: str):
    with create_connection() as db, db.cursor() as cursor:
        cursor.execute(
        f"""
        delete from ti_token_server.users where email = "{email}"
        """)
        db.commit()