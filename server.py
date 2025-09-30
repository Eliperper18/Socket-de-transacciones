import socket
import threading
import json
from user_manager import UserManager
import os
import hmac
import time

from crypto import (load_or_create_psk, derive_session_keys,ReplayCache, verify_signed_action, build_ack_msg)


SESSIONS_LOG = "sessions.log"
TRANSACTIONS_LOG = "transactions.log"

user_manager = UserManager()
sesiones = {}
transacciones = []

HOST = '0.0.0.0'
PORT = 11002

def init_logs():
    # Trunca transactions.log en cada arranque
    with open(TRANSACTIONS_LOG, "w", encoding="utf-8") as f: pass
    if not os.path.exists(SESSIONS_LOG):
        open(SESSIONS_LOG, "w", encoding="utf-8").close()

#if os.path.exists(TRANSACTIONS_LOG):
    #os.remove(TRANSACTIONS_LOG)

def log_session_event(evento: str):
    with open(SESSIONS_LOG, "a") as f:
        f.write(evento + "\n")

def log_transaction(transaccion: str):
    with open(TRANSACTIONS_LOG, "a") as f:
        f.write(transaccion + "\n")

_PSK  = load_or_create_psk()                  # 32 bytes
_KEYS = derive_session_keys(_PSK, "v1")       # {"k_c2s","k_s2c","key_id"}
_REPLAY = ReplayCache(max_items=20000, window_sec=120)
_SKEW   = 60
'''
def handle_client(conn, addr):
    print(f"[+] Cliente con ip {addr} se ha conectado")
    buffer = ""
    try:
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                buffer += data.decode()

                while '\n' in buffer:

                    mensaje, buffer = buffer.split('\n',1)

                    if mensaje.strip():
                        try:
                            obj = json.loads(mensaje)
                            print(f"[{addr}] Mensaje de JSON: {obj}")

                            accion = obj.get("accion")

                            if accion == "register":
                                ok, msg = user_manager.register_user(obj["username"], obj["password"])
                                resp = {"status": "OK" if ok else "ERROR", "mensaje": msg}

                            elif accion == "login":
                                ok, msg = user_manager.verify_credenciales(obj["username"], obj["password"])
                                if ok:
                                    sesiones[addr] = obj["username"]
                                    log_session_event(f"[LOGIN] {obj['username']} desde {addr}")
                                resp = {"status": "OK" if ok else "ERROR", "mensaje": msg}

                            elif accion == "transaccion":
                                if addr not in sesiones:
                                    resp = {"status": "ERROR", "mensaje": "Debes iniciar sesión primero"}
                                else:
                                    # Guardamos la transacción en memoria (después la haremos persistente si quieres)
                                    transaccion = obj.get("data")
                                    usuario = sesiones[addr]
                                    # Ejemplo: "CuentaOrigen, CuentaDestino, Cantidad"
                                    transacciones.append({"usuario": sesiones[addr], "transaccion": transaccion})
                                    log_transaction(f"[TRANSACCION] {usuario}: {transaccion}")
                                    resp = {"status": "OK", "mensaje": f"Transferencia registrada: {transaccion}"}

                            elif accion == "logout":
                                if addr in sesiones:
                                    usuario = sesiones[addr]
                                    del sesiones[addr]
                                    log_session_event(f"[LOGOUT] {usuario} desde {addr}")
                                    resp = {"status": "OK", "mensaje": "Sesión cerrada"}
                                else:
                                    resp = {"status": "ERROR", "mensaje": "No estabas logado"}

                            conn.sendall((json.dumps(resp) + "\n").encode())

                        except Exception as e2:
                            print(f"[!] Ha sucedido un error JSON con {addr}: {e2}")'''
def handle_client(conn, addr):
    print(f"[+] Cliente con ip {addr} se ha conectado")
    buffer = ""
    try:
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                buffer += data.decode()

                while '\n' in buffer:
                    mensaje, buffer = buffer.split('\n', 1)
                    if not mensaje.strip():
                        continue

                    try:
                        obj = json.loads(mensaje)
                        print(f"[{addr}] JSON: {obj}")

                        # --- Ramas originales por 'accion' ---
                        if obj.get("accion") == "register":
                            ok, msg = user_manager.register_user(obj["username"], obj["password"])
                            resp = {"status": "OK" if ok else "ERROR", "mensaje": msg}

                        elif obj.get("accion") == "login":
                            ok, msg = user_manager.verify_credenciales(obj["username"], obj["password"])
                            if ok:
                                sesiones[addr] = obj["username"]
                                log_session_event(f"[LOGIN] {obj['username']} desde {addr}")
                            resp = {"status": "OK" if ok else "ERROR", "mensaje": msg}

                        elif obj.get("accion") == "transaccion":
                            if addr not in sesiones:
                                # no hay sesión -> ACK firmado de error
                                ack = build_ack_msg(_KEYS["k_s2c"], obj, "ERROR", "login requerido", _KEYS["key_id"])
                                conn.sendall((json.dumps(ack) + "\n").encode())
                                continue

                            ok, causa = verify_signed_action(_KEYS["k_c2s"], obj, expected_action="transaccion",
                                                            replay_cache=_REPLAY, skew_sec=_SKEW)
                            if ok:
                                usuario = sesiones[addr]
                                tx = obj["payload"]
                                transacciones.append({"usuario": usuario, "transaccion": tx})
                                log_transaction(f"[TRANSACCION-INT] {usuario}: {tx}")

                                ack = build_ack_msg(_KEYS["k_s2c"], obj, "OK",
                                                    "transferencia registrada con integridad",
                                                    _KEYS["key_id"])
                            else:
                                ack = build_ack_msg(_KEYS["k_s2c"], obj, "ERROR",
                                                    f"tx_rechazada:{causa}",
                                                    _KEYS["key_id"])

                            conn.sendall((json.dumps(ack) + "\n").encode())
                            continue

                        elif obj.get("accion") == "logout":
                            if addr in sesiones:
                                usuario = sesiones.pop(addr)
                                log_session_event(f"[LOGOUT] {usuario} desde {addr}")
                                resp = {"status": "OK", "mensaje": "Sesión cerrada"}
                            else:
                                resp = {"status": "ERROR", "mensaje": "No estabas logado"}

                        # --- NUEVO: transacciones con integridad (type: "tx") ---
                        
                        else:
                            resp = {"status": "ERROR", "mensaje": "acción/type no soportado"}

                        # Respuesta para ramas clásicas
                        conn.sendall((json.dumps(resp) + "\n").encode())

                    except Exception as e2:
                        print(f"[!] Error JSON con {addr}: {e2}")

    except Exception as e:
        print(f"[!] Ha sucedido un error con  {addr}: {e}")
    finally:
        usuario = sesiones[addr]
        del sesiones[addr]
        log_session_event(f"[LOGOUT] {usuario} (desconexión inesperada) desde {addr}")
        print(f"[-] Cliente con ip {addr} se ha desconectado")

def main():
    init_logs();
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[Servidor] Escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == '__main__':
    main()