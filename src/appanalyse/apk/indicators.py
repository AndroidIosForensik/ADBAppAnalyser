"""Mustertabellen zur Erkennung von Chat-/Netzwerkfunktionen im App-Code.

Die Erkennung stuetzt sich auf drei Ebenen, die unterschiedlich robust gegen
Verschleierung sind:

1. Klassen-Praefixe (z. B. ``Lokhttp3/internal/ws/``): eindeutig, aber durch
   Obfuskierung (R8/ProGuard umbenennt) teils entfernt.
2. Protokoll-Signaturen (z. B. die WebSocket-GUID): stehen als Konstanten im
   Code und ueberleben Obfuskierung in aller Regel.
3. Endpunkte und Chat-Begriffe: inhaltliche Hinweise.

Alle Treffer werden mit dem konkreten Fundstueck als Beleg zurueckgegeben.
"""

from __future__ import annotations

import re

# --- Ebene 1: Bibliotheken nach Klassen-/Paket-Praefix --------------------
# Schluessel = Anzeigename, Wert = Liste von Teilstrings, die in DEX-Strings
# (Klassendeskriptoren) vorkommen.
LIBRARIES: dict[str, list[str]] = {
    # Echtzeit-Transport
    "OkHttp WebSocket": ["okhttp3/internal/ws/", "okhttp3/WebSocket"],
    "Java-WebSocket": ["org/java_websocket/"],
    "Socket.IO": ["io/socket/client/", "io/socket/engineio/"],
    "MQTT (Paho)": ["org/eclipse/paho/"],
    "MQTT (HiveMQ)": ["com/hivemq/client/"],
    "XMPP (Smack)": ["org/jivesoftware/smack"],
    "Ktor WebSocket": ["io/ktor/client/plugins/websocket/", "io/ktor/websocket/"],
    "Scarlet WebSocket": ["com/tinder/scarlet/"],
    # Chat-Dienste / Protokolle
    "Firebase Realtime DB": ["com/google/firebase/database/"],
    "Cloud Firestore": ["com/google/firebase/firestore/"],
    "Firebase Cloud Messaging": ["com/google/firebase/messaging/"],
    "Matrix SDK": ["org/matrix/android/sdk/", "org/matrix/rustcomponents/"],
    "libsignal": ["org/signal/libsignal/", "org/whispersystems/"],
    "WebRTC": ["org/webrtc/"],
    # Kommerzielle Chat-SDKs
    "Stream Chat": ["io/getstream/chat/"],
    "Sendbird": ["com/sendbird/android/"],
    "PubNub": ["com/pubnub/api/"],
    "Pusher": ["com/pusher/client/"],
    "Twilio": ["com/twilio/"],
    "CometChat": ["com/cometchat/"],
    "QuickBlox": ["com/quickblox/"],
    "Agora": ["io/agora/rtc", "io/agora/rtm"],
    "Ably": ["io/ably/lib/"],
    # Direktverbindung / Anonymisierung
    "Nearby Connections": ["com/google/android/gms/nearby/"],
    "Tor / Orbot": ["org/torproject/", "info/guardianproject/netcipher/"],
    # Verschluesselung (kontextabhaengig)
    "libsodium": ["com/goterl/lazysodium/", "org/libsodium/"],
    "BouncyCastle": ["org/bouncycastle/"],
    "SQLCipher": ["net/sqlcipher/"],
    "Tink": ["com/google/crypto/tink/"],
    "Conscrypt": ["org/conscrypt/"],
}

# Bibliotheken, die fuer sich genommen Chat-/Echtzeitfunktion nahelegen.
REALTIME_LIBS = {
    "OkHttp WebSocket",
    "Java-WebSocket",
    "Socket.IO",
    "MQTT (Paho)",
    "MQTT (HiveMQ)",
    "XMPP (Smack)",
    "Ktor WebSocket",
    "Scarlet WebSocket",
    "Firebase Realtime DB",
    "Cloud Firestore",
    "Matrix SDK",
    "libsignal",
    "Stream Chat",
    "Sendbird",
    "PubNub",
    "Pusher",
    "CometChat",
    "QuickBlox",
    "Ably",
}

CRYPTO_LIBS = {"libsodium", "BouncyCastle", "SQLCipher", "Tink"}

# --- Ebene 2: Protokoll-Signaturen (ueberstehen Obfuskierung) -------------
# Name -> (Regex, Beschreibung). Auf ASCII beschraenkt, case-sensitiv wo sinnvoll.
PROTOCOL_SIGNATURES: dict[str, str] = {
    "WebSocket-GUID": r"258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
    "WebSocket-Handshake": r"Sec-WebSocket-(?:Key|Accept|Version|Protocol)",
    "MQTT-Protokoll": r"\bMQIsdp\b|\bMQTT\b",
    "XMPP-Stream": r"jabber:client|http://etherx\.jabber\.org/streams",
    "Matrix-API": r"/_matrix/client/",
    "Engine.IO": r"[?&]EIO=\d",
    "STUN/TURN (WebRTC)": r"\bstun:|\bturn:|a=candidate",
    "Signal-Protokoll": r"Curve25519|X3DH|Double Ratchet|WhisperMessage",
}

# --- Ebene 3: Endpunkte ---------------------------------------------------
# WebSocket-/MQTT-URLs, IP:Port-Angaben und generische URLs.
_ENDPOINT_PATTERNS = [
    re.compile(r"wss?://[^\s\"'<>]{4,200}"),
    re.compile(r"mqtts?://[^\s\"'<>]{4,200}"),
    re.compile(r"\bxmpp://[^\s\"'<>]{4,200}"),
    # IP-Adresse mit Port (haeufig bei selbst gehosteten Relays).
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"),
]

# Hosts, die als harmlos gelten und Endpunkt-Treffer nicht ausloesen sollen.
_BENIGN_HOST_RE = re.compile(
    r"(?:^|//|@|\.)("
    r"schemas\.android\.com|w3\.org|apache\.org|google\.com|googleapis\.com|"
    r"gstatic\.com|android\.com|github\.com|githubusercontent\.com|"
    r"mozilla\.org|json-schema\.org|xmlpull\.org|slf4j\.org|"
    r"example\.com|localhost|127\.0\.0\.1|schemas\.xmlsoap\.org|ietf\.org"
    r")",
    re.IGNORECASE,
)

# --- Chat-Begriffe (DE/EN) ------------------------------------------------
# Bewusst spezifische Begriffe: generische Framework-Woerter wie "sendMessage"
# (Handler/Messenger) oder "onMessageReceived" (jede FCM-App) sind zu haeufig und
# erzeugen Fehlalarme, daher NICHT enthalten. Ganze Woerter, keine Teiltreffer.
_CHAT_TERMS = [
    "messagelist", "chatmessage", "chatroom", "chatactivity", "chatfragment",
    "lastseen", "readreceipt", "deliveredreceipt", "groupchat", "directmessage",
    "typingindicator", "onlinestatus", "unreadcount",
    "chatmessages", "sendchat", "newmessage",
    "gruppenchat", "kontaktliste", "gelesen_am", "nachrichtenverlauf",
]
_CHAT_TERM_RE = re.compile(
    r"(?<![a-z])(" + "|".join(re.escape(t) for t in _CHAT_TERMS) + r")(?![a-z])",
    re.IGNORECASE,
)

# --- Tarn-/Deckmantelnamen ------------------------------------------------
# Sichtbare App-Namen, die eine harmlose Funktion vortaeuschen.
CAMOUFLAGE_NAMES = [
    "rechner", "calculator", "taschenrechner",
    "notiz", "notizen", "notes", "memo",
    "taschenlampe", "flashlight", "torch",
    "wetter", "weather",
    "galerie", "gallery", "foto", "photo",
    "system", "android system", "systemdienst", "service", "dienst",
    "update", "aktualisierung", "sync",
    "tresor", "vault", "safe", "locker", "hidden", "versteckt",
    "tools", "werkzeug", "utility", "helfer", "manager",
    "kalender", "calendar", "uhr", "clock", "timer",
    "datei", "files", "cleaner", "reiniger", "optimizer",
]
_CAMOUFLAGE_RE = re.compile(
    r"(?<![a-z])(" + "|".join(re.escape(t) for t in CAMOUFLAGE_NAMES) + r")(?![a-z])",
    re.IGNORECASE,
)

# --- Packer / starke Obfuskierung -----------------------------------------
PACKERS: dict[str, list[str]] = {
    "Jiagu (360)": ["com/stub/StubApp", "libjiagu"],
    "Tencent Legu": ["com/tencent/StubShell", "libshella", "libshellx"],
    "Bangcle/SecShell": ["com/secshell/", "libsecmain", "libSecShell"],
    "Ijiami": ["com/shell/SuperApplication", "libexec.so", "libexecmain"],
    "DexProtector": ["com/licel/dexprotector/"],
    "Alibaba/Mobile Security": ["com/ali/mobisecenhance/", "libmobisec"],
    "AppSealing": ["com/inka/appsealing/"],
}


def match_libraries(strings: list[str]) -> list[tuple[str, str]]:
    """Liefert ``[(Bibliotheksname, Beleg-String)]`` fuer gefundene Bibliotheken."""
    found: dict[str, str] = {}
    for s in strings:
        for name, needles in LIBRARIES.items():
            if name in found:
                continue
            for needle in needles:
                if needle in s:
                    found[name] = s
                    break
    return sorted(found.items())


def match_protocol_signatures(strings: list[str]) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for s in strings:
        for name, pattern in PROTOCOL_SIGNATURES.items():
            if name in found:
                continue
            if re.search(pattern, s):
                found[name] = s[:200]
    return sorted(found.items())


def match_endpoints(strings: list[str], limit: int = 40) -> list[str]:
    """Sammelt auffaellige Endpunkte (ws/mqtt/xmpp/IP:Port), ohne harmlose Hosts."""
    found: set[str] = set()
    for s in strings:
        for pat in _ENDPOINT_PATTERNS:
            for m in pat.findall(s):
                if not _BENIGN_HOST_RE.search(m):
                    found.add(m)
    return sorted(found)[:limit]


def match_chat_terms(strings: list[str], limit: int = 20) -> list[str]:
    found: set[str] = set()
    for s in strings:
        for m in _CHAT_TERM_RE.findall(s):
            found.add(m.lower())
    return sorted(found)[:limit]


def match_camouflage(label: str) -> str:
    """Liefert den getroffenen Tarnbegriff im sichtbaren App-Namen oder ''."""
    m = _CAMOUFLAGE_RE.search(label or "")
    return m.group(1).lower() if m else ""


def match_packer(strings: list[str]) -> str:
    for s in strings:
        for name, needles in PACKERS.items():
            for needle in needles:
                if needle in s:
                    return name
    return ""


def has_embedded_cert(strings: list[str]) -> bool:
    return any("BEGIN CERTIFICATE" in s for s in strings)


def has_pinning(strings: list[str]) -> bool:
    # OkHttp-CertificatePinner-Pins sehen aus wie "sha256/<base64>".
    return any(re.search(r"sha256/[A-Za-z0-9+/=]{20,}", s) for s in strings)
