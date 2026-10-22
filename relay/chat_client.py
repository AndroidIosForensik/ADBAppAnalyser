#!/usr/bin/env python3
"""Kommandozeilen-Chatclient fuer den Relay-Server.

Zweck: den Server ohne Handy testen und als Baustein fuer den E2E-Test dienen.
Verbindet sich per WSS (Zertifikat pruefbar oder mit --insecure fuer Selbstsignat),
meldet sich mit Nutzername + Token an und sendet/empfaengt Nachrichten.

Beispiel:
  python chat_client.py --url wss://203.0.113.7:8443 --user alice --token T --cafile relay_cert.pem
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import uuid

from websockets.asyncio.client import connect


class ChatClient:
    def __init__(self, url: str, user: str, token: str, ssl_ctx=None):
        self.url = url
        self.user = user
        self.token = token
        self.ssl_ctx = ssl_ctx
        self.ws = None

    async def __aenter__(self):
        self.ws = await connect(self.url, ssl=self.ssl_ctx, max_size=16 * 1024)
        await self.ws.send(json.dumps({"type": "hello", "user": self.user, "token": self.token}))
        reply = json.loads(await self.ws.recv())
        if reply.get("type") != "hello_ok":
            raise RuntimeError(f"Anmeldung fehlgeschlagen: {reply.get('reason')}")
        return self

    async def __aexit__(self, *exc):
        if self.ws is not None:
            await self.ws.close()

    async def send(self, to: str, text: str) -> str:
        mid = uuid.uuid4().hex
        await self.ws.send(json.dumps({"type": "msg", "to": to, "id": mid, "text": text}))
        return mid

    async def recv(self):
        return json.loads(await self.ws.recv())


def _ssl_context(cafile: str, insecure: bool):
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if cafile:
        return ssl.create_default_context(cafile=cafile)
    return ssl.create_default_context()


async def _interactive(args) -> None:
    ctx = _ssl_context(args.cafile, args.insecure)
    async with ChatClient(args.url, args.user, args.token, ctx) as client:
        print(f"Angemeldet als {args.user}. Eingabe: '<empfaenger> <text>' oder /quit")

        async def reader():
            while True:
                msg = await client.recv()
                if msg.get("type") == "msg":
                    print(f"\n[{msg['from']}] {msg['text']}\n> ", end="", flush=True)
                elif msg.get("type") == "presence":
                    state = "online" if msg["online"] else "offline"
                    print(f"\n* {msg['user']} ist {state}\n> ", end="", flush=True)

        task = asyncio.create_task(reader())
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line or line.strip() == "/quit":
                break
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                await client.send(parts[0], parts[1])
        task.cancel()


def main() -> None:
    parser = argparse.ArgumentParser(description="Relay-Chatclient (Test)")
    parser.add_argument("--url", required=True, help="z. B. wss://203.0.113.7:8443")
    parser.add_argument("--user", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--cafile", default="", help="PEM des Server-Zertifikats")
    parser.add_argument("--insecure", action="store_true", help="Zertifikat nicht pruefen")
    args = parser.parse_args()
    try:
        asyncio.run(_interactive(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
