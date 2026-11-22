import hashlib
import secrets
import threading
import time
from collections import deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
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
LOGIN_WINDOW = 60
LOGIN_FAILURE_LIMIT = 6
_login_failures: dict[tuple[str, str], deque[float]] = {}
_login_guard = threading.Lock()


def _record_login(key, valid=None):
    """Bound failed logins per source and account; use monotonic time."""
    now = time.monotonic()
    with _login_guard:
        if valid is True:
            _login_failures.pop(key, None)
            return False
        recent = _login_failures.get(key, deque())
        while recent and now - recent[0] >= LOGIN_WINDOW:
            recent.popleft()
        if valid is False:
            recent.append(now)
        if recent:
            _login_failures[key] = recent
        else:
            _login_failures.pop(key, None)
        if len(_login_failures) > 2048:
            for candidate, stamps in list(_login_failures.items()):
                if not stamps or now - stamps[-1] >= LOGIN_WINDOW:
                    del _login_failures[candidate]
            while len(_login_failures) > 2048:
                _login_failures.pop(next(iter(_login_failures)))
        return len(recent) >= LOGIN_FAILURE_LIMIT


def _has_accounts(engine):
    with engine.connect() as db:
        return db.scalar(select(users.c.id).limit(1)) is not None



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


@router.get("/setup")
def setup(request: Request):
    return {"needs_initial_account": not _has_accounts(request.app.state.db)}


@router.post("/register", status_code=201)
def register(body: Credentials, request: Request, response: Response):
    is_initialized = _has_accounts(request.app.state.db)
    if is_initialized and identify(request.app.state.db, request.cookies.get(COOKIE)) is None:
        raise HTTPException(403, "已有本地账户，请登录后在设置中添加新账户")
    encoded = hasher.hash(body.password)
    try:
        with request.app.state.db.begin() as db:
            result = db.execute(insert(users).values(username=body.username, hash=encoded))
            if not is_initialized:
                issue(db, result.inserted_primary_key[0], response)
    except IntegrityError:
        raise HTTPException(409, "用户名已被使用") from None
    request.app.state.monitor.log("account.register", "已创建本地工作台账户")
    return {"username": body.username}


@router.post("/login")
def login(body: Credentials, request: Request, response: Response):
    key = (request.client.host if request.client else "local", body.username)
    if _record_login(key):
        raise HTTPException(429, "登录尝试过于频繁，请稍后重试", headers={"Retry-After": "60"})
    with request.app.state.db.connect() as db:
        user = db.execute(select(users).where(users.c.username == body.username)).mappings().first()
    valid = False
    if user is not None:
        try:
            valid = hasher.verify(user["hash"], body.password)
        except (VerificationError, InvalidHashError):
            valid = False
    if not valid:
        _record_login(key, False)
        raise HTTPException(401, "用户名或密码有误")
    _record_login(key, True)
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
