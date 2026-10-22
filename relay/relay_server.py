#!/usr/bin/env python3
"""Minimaler TLS-WebSocket-Relay fuer die Test-Chat-App.

Zwei Android-Geraete verbinden sich per WSS zum Server (feste IPv4) und tauschen
JSON-Nachrichten aus: Geraet -> Server -> Geraet. Der Server speichert nichts auf
Platte und protokolliert keine Nachrichteninhalte.

Protokoll (JSON, je WebSocket-Textframe eine Nachricht):
  Client -> Server: {"type":"hello","user":"alice","token":"..."}
                    {"type":"msg","to":"bob","id":"<uuid>","text":"..."}
                    {"type":"ack","id":"<uuid>"}
  Server -> Client: {"type":"hello_ok"} | {"type":"error","reason":"..."}
                    {"type":"msg","from":"alice","id":"...","text":"..."}
                    {"type":"presence","user":"bob","online":true}
                    {"type":"ack","id":"..."}

Nur fuer Testzwecke auf Geraeten/Servern, die der Betreiber selbst kontrolliert.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import logging
import os
import re
import ssl
import time
from collections import deque

try:
    from websockets.asyncio.server import serve
except ImportError:  # pragma: no cover - aeltere websockets-Version
    raise SystemExit("Benoetigt websockets >= 13 (pip install 'websockets>=13').")

log = logging.getLogger("relay")

USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MAX_MSG_BYTES = 16 * 1024
MAX_CONNECTIONS = 100
RATE_WINDOW = 10.0
RATE_MAX = 60  # Nachrichten pro Fenster und Verbindung
QUEUE_TTL = 24 * 3600
QUEUE_MAX_PER_USER = 200


class Relay:
    def __init__(self, token: str):
        self.token = token
        self.online: dict[str, object] = {}  # user -> websocket
        self.queues: dict[str, deque] = {}  # user -> deque[(ts, payload)]

    async def handle(self, ws) -> None:
        if len(self.online) >= MAX_CONNECTIONS:
            await _send(ws, {"type": "error", "reason": "server_full"})
            return
        user = await self._authenticate(ws)
        if not user:
            return
        # Vorherige Verbindung desselben Nutzers ersetzen.
        old = self.online.get(user)
        if old is not None:
            await _close(old)
        self.online[user] = ws
        log.info("verbunden: %s (%d online)", user, len(self.online))
        await self._broadcast_presence(user, True)
        await self._flush_queue(user, ws)
        try:
            await self._pump(user, ws)
        finally:
            if self.online.get(user) is ws:
                del self.online[user]
            log.info("getrennt: %s (%d online)", user, len(self.online))
            await self._broadcast_presence(user, False)

    async def _authenticate(self, ws):
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=15)
        except (asyncio.TimeoutError, Exception):
            return None
        if isinstance(raw, bytes) or len(raw) > MAX_MSG_BYTES:
            await _send(ws, {"type": "error", "reason": "bad_hello"})
            return None
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            await _send(ws, {"type": "error", "reason": "bad_json"})
            return None
        user = msg.get("user", "")
        token = msg.get("token", "")
        if msg.get("type") != "hello" or not USER_RE.match(str(user)):
            await _send(ws, {"type": "error", "reason": "bad_user"})
            return None
        # Konstantzeit-Vergleich des Tokens.
        if not hmac.compare_digest(str(token), self.token):
            await _send(ws, {"type": "error", "reason": "auth"})
            return None
        await _send(ws, {"type": "hello_ok"})
        return user

    async def _pump(self, user: str, ws) -> None:
        times: deque[float] = deque()
        async for raw in ws:
            if isinstance(raw, bytes) or len(raw) > MAX_MSG_BYTES:
                await _send(ws, {"type": "error", "reason": "too_large"})
                continue
            now = time.monotonic()
            times.append(now)
            while times and now - times[0] > RATE_WINDOW:
                times.popleft()
            if len(times) > RATE_MAX:
                await _send(ws, {"type": "error", "reason": "rate_limited"})
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            await self._route(user, msg, ws)

    async def _route(self, sender: str, msg: dict, ws) -> None:
        mtype = msg.get("type")
        if mtype in ("msg", "ack"):
            to = str(msg.get("to", ""))
            if not USER_RE.match(to):
                await _send(ws, {"type": "error", "reason": "bad_to"})
                return
            payload = {"type": mtype, "from": sender, "id": str(msg.get("id", ""))}
            if mtype == "msg":
                text = msg.get("text", "")
                if not isinstance(text, str) or len(text) > MAX_MSG_BYTES:
                    await _send(ws, {"type": "error", "reason": "bad_text"})
                    return
                payload["text"] = text
            await self._deliver(to, payload)
        elif mtype == "ping":
            await _send(ws, {"type": "pong"})

    async def _deliver(self, to: str, payload: dict) -> None:
        target = self.online.get(to)
        if target is not None:
            await _send(target, payload)
            return
        # Empfaenger offline: begrenzt puffern (nur RAM, mit TTL).
        q = self.queues.setdefault(to, deque())
        q.append((time.time(), payload))
        while len(q) > QUEUE_MAX_PER_USER:
            q.popleft()

    async def _flush_queue(self, user: str, ws) -> None:
        q = self.queues.pop(user, None)
        if not q:
            return
        now = time.time()
        for ts, payload in q:
            if now - ts <= QUEUE_TTL:
                await _send(ws, payload)

    async def _broadcast_presence(self, user: str, online: bool) -> None:
        note = {"type": "presence", "user": user, "online": online}
        for other, ws in list(self.online.items()):
            if other != user:
                await _send(ws, note)


async def _send(ws, payload: dict) -> None:
    try:
        await ws.send(json.dumps(payload))
    except Exception:
        pass


async def _close(ws) -> None:
    try:
        await ws.close()
    except Exception:
        pass


def _load_token(args) -> str:
    if args.token:
        return args.token
    env = os.environ.get("RELAY_TOKEN")
    if env:
        return env
    if args.token_file and os.path.exists(args.token_file):
        return open(args.token_file, encoding="utf-8").read().strip()
    raise SystemExit("Kein Token gesetzt (--token, RELAY_TOKEN oder --token-file).")


def _make_ssl(cert: str, key: str) -> ssl.SSLContext | None:
    if not cert or not key:
        log.warning("Kein Zertifikat angegeben - Server laeuft UNVERSCHLUESSELT (ws://).")
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


async def _run(args) -> None:
    token = _load_token(args)
    relay = Relay(token)
    ssl_ctx = _make_ssl(args.cert, args.key)
    scheme = "wss" if ssl_ctx else "ws"
    async with serve(
        relay.handle, args.host, args.port, ssl=ssl_ctx, max_size=MAX_MSG_BYTES
    ):
        log.info("Relay laeuft auf %s://%s:%d", scheme, args.host, args.port)
        await asyncio.Future()  # laeuft bis Signal


def main() -> None:
    parser = argparse.ArgumentParser(description="TLS-WebSocket-Relay fuer die Test-Chat-App")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default=os.environ.get("RELAY_CERT", ""))
    parser.add_argument("--key", default=os.environ.get("RELAY_KEY", ""))
    parser.add_argument("--token", default="")
    parser.add_argument("--token-file", default=os.environ.get("RELAY_TOKEN_FILE", ""))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
