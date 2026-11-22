import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import URL, create_engine, event
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import auth, monitor_api, packets, speed
from .telemetry import Monitor

DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


def create_app(db_path=None):
    @asynccontextmanager
    async def lifespan(app):
        path = Path(db_path or os.environ.get("NETSCOPE_DB", "data/netscope.sqlite3"))
        path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(URL.create("sqlite", database=str(path)), connect_args={"timeout": 10})

        @event.listens_for(engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=10000")

        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        auth.metadata.create_all(engine)
        app.state.db = engine
        monitor = app.state.monitor = Monitor(engine)
        capture = app.state.capture = packets.Capture(engine)
        test = app.state.speed = speed.SpeedTest(engine, monitor.log)
        await monitor.start()
        try:
            yield
        finally:
            await test.close()
            await asyncio.to_thread(capture.close)
            await monitor.stop()
            engine.dispose()

    app = FastAPI(title="NetScope", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        fields = [".".join(map(str, item["loc"][1:])) for item in exc.errors()]
        return JSONResponse({"detail": "请检查输入字段 " + "、".join(fields)}, status_code=422)

    def origin_allowed(headers):
        origin = headers.get("origin")
        return origin is None or origin == f"http://{headers.get('host')}"

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not origin_allowed(request.headers):
            return JSONResponse({"detail": "请求来源与本机工作台不符"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.include_router(auth.router, prefix="/api")
    for router in [monitor_api.router, packets.router, speed.router]:
        app.include_router(router, prefix="/api", dependencies=[Depends(auth.authenticated)])

    @app.websocket("/api/live")
    async def live(ws: WebSocket):
        if not origin_allowed(ws.headers) or not auth.identify(
            ws.app.state.db, ws.cookies.get(auth.COOKIE)
        ):
            await ws.close(code=1008)
            return
        await ws.accept()
        try:
            while True:
                await ws.send_json(ws.app.state.monitor.snapshot())
                await asyncio.sleep(1)
                if not auth.identify(ws.app.state.db, ws.cookies.get(auth.COOKIE)):
                    await ws.close(code=1008)
                    return
        except WebSocketDisconnect:
            pass

    @app.get("/{resource:path}", include_in_schema=False)
    def frontend(resource: str):
        if resource == "api" or resource.startswith("api/"):
            raise HTTPException(404)
        file = (DIST / resource).resolve()
        if not file.is_relative_to(DIST) or resource.startswith("."):
            raise HTTPException(404)
        if file.is_file():
            return FileResponse(file)
        index = DIST / "index.html"
        if not index.is_file():
            raise HTTPException(503, "请先在 frontend 目录运行 npm ci 和 npm run build")
        if Path(resource).suffix:
            raise HTTPException(404)
        return FileResponse(index)

    return app


app = create_app()
