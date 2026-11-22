import hashlib
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    delete,
    insert,
    select,
)
from sqlalchemy.exc import IntegrityError

router = APIRouter(prefix="/auth")
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, nullable=False, unique=True),
    Column("hash", String, nullable=False),
)
sessions = Table(
    "sessions",
    metadata,
    Column("digest", String, primary_key=True),
    Column("user_id", ForeignKey("users.id"), nullable=False),
    Column("expires", Float, nullable=False),
)
hasher = PasswordHasher()
COOKIE = "netscope_session"
TTL = 12 * 3600


class Credentials(BaseModel):
    username: str = Field(min_length=2, max_length=40, pattern=r"^[\w.-]+$")
    password: str = Field(min_length=8, max_length=128)


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def identify(engine, token):
    if not token:
        return None
    with engine.connect() as db:
        return db.scalar(
            select(users.c.username)
            .join(sessions)
            .where(sessions.c.digest == digest(token), sessions.c.expires > time.time())
        )


def authenticated(request: Request):
    name = identify(request.app.state.db, request.cookies.get(COOKIE))
    if name is None:
        raise HTTPException(401, "请先登录本机工作台")
    return name


def issue(db, user_id, response):
    token = secrets.token_urlsafe(32)
    db.execute(delete(sessions).where(sessions.c.expires <= time.time()))
    db.execute(
        insert(sessions).values(digest=digest(token), user_id=user_id, expires=time.time() + TTL)
    )
    response.set_cookie(COOKIE, token, max_age=TTL, httponly=True, samesite="strict", path="/api")


@router.post("/register", status_code=201)
def register(body: Credentials, request: Request, response: Response):
    encoded = hasher.hash(body.password)
    try:
        with request.app.state.db.begin() as db:
            result = db.execute(insert(users).values(username=body.username, hash=encoded))
            issue(db, result.inserted_primary_key[0], response)
    except IntegrityError:
        raise HTTPException(409, "用户名已被使用") from None
    request.app.state.monitor.log("account.register", "已创建本地工作台账户")
    return {"username": body.username}


@router.post("/login")
def login(body: Credentials, request: Request, response: Response):
    with request.app.state.db.connect() as db:
        user = db.execute(select(users).where(users.c.username == body.username)).mappings().first()
    if user is None:
        raise HTTPException(401, "用户名或密码有误")
    try:
        hasher.verify(user["hash"], body.password)
    except VerifyMismatchError:
        raise HTTPException(401, "用户名或密码有误") from None
    with request.app.state.db.begin() as db:
        issue(db, user["id"], response)
    request.app.state.monitor.log("account.login", "已登录本地工作台")
    return {"username": user["username"]}


@router.get("/me")
def me(username: str = Depends(authenticated)):
    return {"username": username}


@router.post("/logout")
def logout(request: Request, response: Response):
    with request.app.state.db.begin() as db:
        db.execute(delete(sessions).where(sessions.c.digest == digest(request.cookies.get(COOKIE, ""))))
    response.delete_cookie(COOKIE, path="/api")
    return {"ok": True}
