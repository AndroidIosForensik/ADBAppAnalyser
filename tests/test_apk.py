"""Tests der APK-Bausteine: Indikator-Mustererkennung und DEX-String-Leser.

Der DEX-Leser wird gegen einen von Hand gebauten Minimal-DEX geprueft, damit die
Binaerlogik (Header-Offsets, ULEB128, Nullterminierung) ohne echte APK abgedeckt
ist.
"""

from __future__ import annotations

import struct

from appanalyse.apk import indicators
from appanalyse.apk.dex_strings import iter_dex_strings
from appanalyse.apk.native_strings import detect_code_kind


# -- Indikatoren ----------------------------------------------------------


def test_bibliothek_okhttp_ws():
    strings = ["Lokhttp3/internal/ws/RealWebSocket;", "Landroidx/core/App;"]
    libs = dict(indicators.match_libraries(strings))
    assert "OkHttp WebSocket" in libs
    assert libs["OkHttp WebSocket"].startswith("Lokhttp3")


def test_protokoll_signatur_ueberlebt_obfuskierung():
    # Selbst wenn Klassennamen obfuskiert sind, bleibt die GUID als Konstante.
    strings = ["La;", "Lb/c;", "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"]
    sigs = dict(indicators.match_protocol_signatures(strings))
    assert "WebSocket-GUID" in sigs


def test_endpunkte_filtern_harmlose_hosts():
    strings = [
        "wss://relay.meinserver.de:8443/ws",
        "http://schemas.android.com/apk/res/android",  # harmlos
        "203.0.113.7:8443",
    ]
    eps = indicators.match_endpoints(strings)
    assert "wss://relay.meinserver.de:8443/ws" in eps
    assert "203.0.113.7:8443" in eps
    assert not any("schemas.android.com" in e for e in eps)


def test_chat_begriffe_ganzes_wort():
    strings = ["class ChatMessage {", "readReceipt=true", "Handler.sendMessage()"]
    terms = indicators.match_chat_terms(strings)
    assert "chatmessage" in terms
    assert "readreceipt" in terms
    # Generische Framework-Begriffe wie sendMessage duerfen NICHT zaehlen.
    assert not any("send" in t for t in terms)


def test_tarnnamen():
    assert indicators.match_camouflage("Rechner") == "rechner"
    assert indicators.match_camouflage("Taschenlampe Pro") == "taschenlampe"
    assert indicators.match_camouflage("WhatsApp") == ""


def test_packer_und_pinning():
    assert indicators.match_packer(["com/stub/StubApp"]) == "Jiagu (360)"
    assert indicators.has_pinning(["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]) is True
    assert indicators.has_embedded_cert(["-----BEGIN CERTIFICATE-----"]) is True


def test_code_kind():
    assert detect_code_kind(["assets/flutter_assets/kernel_blob.bin"]) == "flutter"
    assert detect_code_kind(["assets/index.android.bundle"]) == "react-native"
    assert detect_code_kind(["classes.dex", "AndroidManifest.xml"]) == "dex"


# -- DEX-String-Leser -----------------------------------------------------


def _build_dex(strings: list[str]) -> bytes:
    """Baut einen minimalen, fuer unseren Leser gueltigen DEX-Blob."""
    header_size = 112
    ids_off = header_size
    ids_table_size = len(strings) * 4
    data_start = ids_off + ids_table_size

    data_blob = b""
    offsets = []
    for s in strings:
        offsets.append(data_start + len(data_blob))
        raw = s.encode("utf-8")
        data_blob += _uleb128(len(s)) + raw + b"\x00"

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x38, len(strings))  # string_ids_size
    struct.pack_into("<I", header, 0x3C, ids_off)  # string_ids_off

    ids_table = b"".join(struct.pack("<I", off) for off in offsets)
    return bytes(header) + ids_table + data_blob


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def test_dex_reader_liest_strings():
    strings = ["Lokhttp3/internal/ws/RealWebSocket;", "wss://relay:8443", "hallo"]
    blob = _build_dex(strings)
    got = list(iter_dex_strings(blob))
    assert set(got) == set(strings)


def test_dex_reader_ignoriert_muell():
    assert list(iter_dex_strings(b"not a dex file at all")) == []
    assert list(iter_dex_strings(b"")) == []
