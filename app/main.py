"""
FastAPI application entry point.

Registers:
  • REST routers (rooms, chat, files, security)
  • WebSocket endpoint for real-time messaging
  • Static frontend files
  • Startup / shutdown hooks
"""
import asyncio
import logging
import logging.handlers
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.storage.database import init_db
from app.security.nonce_manager import nonce_manager
from app.websocket.websocket_manager import ws_manager
from app.controllers.room_controller import router as room_router
from app.controllers.chat_controller import router as chat_router
from app.controllers.file_controller import router as file_router
from app.controllers.security_controller import router as security_router


# ─────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────
def _configure_logging() -> None:
    log_dir = Path(settings.LOG_FILE).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s – %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Console
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Rotating file – captures all [SECURITY] events
    fh = logging.handlers.RotatingFileHandler(
        settings.LOG_FILE, maxBytes=5_000_000, backupCount=3
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)


_configure_logging()
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Background task – periodic nonce cleanup
# ─────────────────────────────────────────────
async def _nonce_cleanup_loop() -> None:
    """Purge expired nonces every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        removed = nonce_manager.purge_expired()
        if removed:
            logger.debug("[NONCE] Purged %d expired nonces", removed)


# ─────────────────────────────────────────────
# Application lifespan
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=== Secure Chat Demo starting ===")
    init_db()
    task = asyncio.create_task(_nonce_cleanup_loop())
    yield
    task.cancel()
    logger.info("=== Secure Chat Demo shutting down ===")


# ─────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST routers
app.include_router(room_router)
app.include_router(chat_router)
app.include_router(file_router)
app.include_router(security_router)


# ─────────────────────────────────────────────
# WebSocket endpoint
# ─────────────────────────────────────────────
@app.websocket("/ws/{room_id}/{user_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, user_id: str):
    """
    Real-time bidirectional channel.
    URL: ws://<host>/ws/<room_id>/<user_id>
    """
    await ws_manager.connect(websocket, room_id, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            await ws_manager.handle_message(data, room_id, user_id)
    except WebSocketDisconnect:
        await ws_manager.disconnect(room_id, user_id)
    except Exception as exc:
        logger.error("[WS] Unexpected error: %s", exc)
        await ws_manager.disconnect(room_id, user_id)


# ─────────────────────────────────────────────
# Frontend static files + SPA fallback
# ─────────────────────────────────────────────
frontend_dir = Path(settings.FRONTEND_DIR)
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_index():
        return FileResponse(str(frontend_dir / "index.html"))


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME}
