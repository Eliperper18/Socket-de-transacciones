# crypto_utils.py
import os, hmac, hashlib, json, time, base64
from collections import deque

# ---------- JSON canónico ----------
def canon(obj) -> bytes:
    # JSON estable para firmar: sin espacios, claves ordenadas
    return json.dumps(obj, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

# ---------- HMAC SHA-256 ----------
# Recibe una clave secreta y un mensaje a auntenticar y devuleve hash de 32 bytes.
def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()
# pasa de bytes a string
def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
# pasa de string a bytes
def b64d(s: str) -> bytes: return base64.b64decode(s.encode(), validate=True)

# ---------- HKDF (SHA-256) ----------
# hkdf_extract --> Recibe un "salt" en bytes para más seguridad 
                # recibe una un salt 
                # recibe una calve maestra 
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()
    

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t = b"", b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)

# ---------- Claves (PSK 256 bits + derivación C2S/S2C) ----------
def load_or_create_psk(path="secret.key") -> bytes:
    """
    Carga/crea una PSK de 32 bytes. También permite pasarla por env PAI_PSK (hex o texto).
    """
    env = os.getenv("PAI_PSK")
    if env:
        try:
            raw = bytes.fromhex(env)
        except ValueError:
            raw = env.encode()
        return hashlib.sha256(raw).digest()  # normaliza a 32B
    if os.path.exists(path):
        return open(path, "rb").read()
    key = os.urandom(32)
    with open(path, "wb") as f: f.write(key)
    return key

def derive_session_keys(psk: bytes, key_id: str = "v1") -> dict:
    """
    Deriva claves separadas para cliente->servidor y servidor->cliente (256 bits).
    """
    salt = hashlib.sha256(b"PAI1-salt-" + key_id.encode()).digest()
    prk  = hkdf_extract(salt, psk)
    k_c2s = hkdf_expand(prk, b"PAI1 c2s " + key_id.encode(), 32)
    k_s2c = hkdf_expand(prk, b"PAI1 s2c " + key_id.encode(), 32)
    return {"key_id": key_id, "k_c2s": k_c2s, "k_s2c": k_s2c}

# ---------- Anti-replay cache ----------
class ReplayCache:
    """
    LRU por tiempo para nonces (bytes). Sirve tanto en servidor como cliente.
    """
    def __init__(self, max_items=10000, window_sec=120):
        self.max_items = max_items
        self.window_sec = window_sec
        self.q = deque()   # (nonce_bytes, ts)
        self.set = set()

    def _evict(self, now_ts: int):
        while self.q and (now_ts - self.q[0][1] > self.window_sec):
            n, _ = self.q.popleft()
            self.set.discard(n)
        while len(self.q) > self.max_items:
            n, _ = self.q.popleft()
            self.set.discard(n)

    def seen_or_add(self, nonce_bytes: bytes, now_ts: int) -> bool:
        self._evict(now_ts)
        if nonce_bytes in self.set:
            return True
        self.set.add(nonce_bytes)
        self.q.append((nonce_bytes, now_ts))
        return False

class AckReplayCache:
    def __init__(self, max_items=10000, window_sec=120):
        from collections import deque
        self.max_items = max_items
        self.window_sec = window_sec
        self.q = deque()  # (rx_nonce_bytes, ts)
        self.set = set()

    def _evict(self, now_ts):
        while self.q and (now_ts - self.q[0][1] > self.window_sec):
            n, _ = self.q.popleft()
            self.set.discard(n)
        while len(self.q) > self.max_items:
            n, _ = self.q.popleft()
            self.set.discard(n)

    def seen_or_add(self, nonce_bytes, now_ts):
        self._evict(now_ts)
        if nonce_bytes in self.set:
            return True
        self.set.add(nonce_bytes)
        self.q.append((nonce_bytes, now_ts))
        return False

def verify_ack(k_s2c: bytes, ack: dict, pending_nonces: set, ack_cache: AckReplayCache, skew_sec=60):
    import hmac, time
    for f in ("type","status","info","rx_nonce","ts","key_id","mac"):
        if f not in ack:
            return False, f"missing:{f}"

    # 1) Verificar MAC del ACK
    body = {k: ack[k] for k in ("type","status","info","rx_nonce","ts","key_id")}
    mac_rx = b64d(ack["mac"])
    mac_ok = hmac.compare_digest(hmac256(k_s2c, canon(body)), mac_rx)
    if not mac_ok:
        return False, "mac"

    # 2) Ventana temporal del ACK
    try:
        ts = int(ack["ts"])
    except Exception:
        return False, "ts-format"
    now = int(time.time())
    if abs(now - ts) > skew_sec:
        return False, "ts-skew"

    # 3) Anti-replay (ACK duplicado) + correspondencia con petición pendiente
    try:
        rxn = b64d(ack["rx_nonce"])
    except Exception:
        return False, "b64"

    # Debe corresponder a una petición pendiente
    if ack["rx_nonce"] not in pending_nonces:
        return False, "unknown-request"

    # No debe haberse visto antes
    if ack_cache.seen_or_add(rxn, ts):
        return False, "replay"

    # Si todo OK, el nonce deja de estar pendiente
    pending_nonces.discard(ack["rx_nonce"])
    return True, "ok"

# ---------- Construcción de mensajes TX y ACK ----------
def build_signed_action(k_c2s: bytes, action: str, payload: dict, key_id: str) -> dict:
    ts = int(time.time())
    nonce = os.urandom(12)
    body = {"accion": action, "payload": payload, "ts": ts, "nonce": b64e(nonce), "key_id": key_id}
    mac  = hmac256(k_c2s, canon(body))
    body["mac"] = b64e(mac)
    return body


def build_ack_msg(k_s2c: bytes, req_msg: dict, status: str, info: str, key_id: str) -> dict:
    """
    ACK autenticado por el servidor. Echa eco del nonce recibido:
    {
      "type":"ack","status":"OK/ERROR","info":"...","rx_nonce":"...",
      "ts":<epoch>,"key_id":"v1","mac":"..."
    }
    """
    ack = {
        "type": "ack",
        "status": status,
        "info": info,
        "rx_nonce": req_msg.get("nonce", ""),
        "ts": int(time.time()),
        "key_id": key_id
    }
    ack["mac"] = b64e(hmac256(k_s2c, canon(ack)))
    return ack

# ---------- Verificación del mensaje de TX (servidor) ----------
def verify_signed_action(k_c2s: bytes, msg: dict, expected_action: str, replay_cache: ReplayCache, skew_sec=60):
    """
    Verifica una petición firmada con 'accion' == expected_action.
    Devuelve (ok: bool, causa: str)
    """
    for f in ("accion","payload","ts","nonce","mac","key_id"):
        if f not in msg:
            return False, f"missing:{f}"
    if msg["accion"] != expected_action:
        return False, "accion"

    try:
        ts = int(msg["ts"])
    except Exception:
        return False, "ts-format"

    now = int(time.time())
    if abs(now - ts) > skew_sec:
        return False, "ts-skew"

    try:
        nonce = b64d(msg["nonce"])
        mac_rx = b64d(msg["mac"])
    except Exception:
        return False, "b64"

    body = {k: msg[k] for k in ("accion","payload","ts","nonce","key_id")}
    mac_calc = hmac256(k_c2s, canon(body))

    if not hmac.compare_digest(mac_rx, mac_calc):
        return False, "mac"

    if replay_cache.seen_or_add(nonce, ts):
        return False, "replay"

    return True, "ok"

