"""End-to-End-Test des Relay-Servers mit zwei echten TLS-WebSocket-Clients.

Startet den Server aus relay/ auf einem zufaelligen Port mit selbstsigniertem
Zertifikat und prueft: Anmeldung, Zustellung in beide Richtungen und Pufferung
fuer einen kurz offline gegangenen Empfaenger.
"""

from __future__ import annotations

import asyncio
import datetime
import importlib.util
import ipaddress
import pathlib
import ssl
import sys

import pytest

RELAY_DIR = pathlib.Path(__file__).resolve().parent.parent / "relay"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, RELAY_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_cert(tmp_path) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


async def _run_scenario(cert_file: str, key_file: str) -> dict:
    relay_server = _load("relay_server")
    chat_client = _load("chat_client")

    token = "geheim-token"
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_file, key_file)
    relay = relay_server.Relay(token)

    from websockets.asyncio.server import serve

    results: dict = {}
    async with serve(relay.handle, "127.0.0.1", 0, ssl=server_ctx) as server:
        port = server.sockets[0].getsockname()[1]
        url = f"wss://127.0.0.1:{port}"
        client_ctx = ssl.create_default_context(cafile=cert_file)

        # 1) Beide online: Zustellung in beide Richtungen.
        async with chat_client.ChatClient(url, "alice", token, client_ctx) as alice, \
                chat_client.ChatClient(url, "bob", token, client_ctx) as bob:
            # Presence-Nachricht (bob wird online) bei alice abholen, dann Chat.
            await alice.send("bob", "hallo bob")
            got = await _next_msg(bob)
            results["bob_recv"] = got
            await bob.send("alice", "hallo alice")
            results["alice_recv"] = await _next_msg(alice)

        # 2) Empfaenger offline: Nachricht wird gepuffert und spaeter zugestellt.
        async with chat_client.ChatClient(url, "alice", token, client_ctx) as alice:
            await alice.send("carol", "bis gleich")
        await asyncio.sleep(0.1)
        async with chat_client.ChatClient(url, "carol", token, client_ctx) as carol:
            results["carol_queued"] = await _next_msg(carol)

        # 3) Falsches Token wird abgewiesen.
        try:
            async with chat_client.ChatClient(url, "mallory", "falsch", client_ctx):
                results["auth_rejected"] = False
        except RuntimeError:
            results["auth_rejected"] = True

    return results


async def _next_msg(client, timeout: float = 5.0) -> dict:
    """Wartet auf die naechste 'msg'-Nachricht (Presence u. a. ueberspringen)."""
    while True:
        msg = await asyncio.wait_for(client.recv(), timeout)
        if msg.get("type") == "msg":
            return msg


@pytest.mark.skipif(
    importlib.util.find_spec("websockets") is None, reason="websockets nicht installiert"
)
def test_relay_end_to_end(tmp_path):
    cert_file, key_file = _make_cert(tmp_path)
    results = asyncio.run(_run_scenario(cert_file, key_file))
    assert results["bob_recv"]["from"] == "alice"
    assert results["bob_recv"]["text"] == "hallo bob"
    assert results["alice_recv"]["text"] == "hallo alice"
    assert results["carol_queued"]["text"] == "bis gleich"  # Offline-Pufferung
    assert results["auth_rejected"] is True
