import socket
import json
import hmac

from crypto import (load_or_create_psk, derive_session_keys, build_signed_action, b64d, canon, hmac256, AckReplayCache, verify_ack)

HOST = '127.0.0.1'
PORT = 11002
pending = set()            # nonces (base64) de peticiones en vuelo
ack_seen = AckReplayCache(window_sec=120)
def main():
    
    psk  = load_or_create_psk()
    keys = derive_session_keys(psk, key_id="v1")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST,PORT))

        print("[Cliente] Conectado al servidor")

        while True:
            accion = input("Acción (register/login/transaccion/logout/salir): ")

            if accion == "salir":
                print("[Cliente] Cerrando conexión...")
                break

            if accion == "register":
                username = input("Nuevo usuario: ")
                password = input("Contraseña: ")
                msg = {"accion": "register", "username": username, "password": password}

            elif accion == "login":
                username = input("Usuario: ")
                password = input("Contraseña: ")
                msg = {"accion": "login", "username": username, "password": password}

            elif accion == "transaccion":
                from_acc = input("Cuenta ORIGEN: ")
                to_acc   = input("Cuenta DESTINO: ")
                amount   = float(input("Cantidad: "))
                payload  = {"from": from_acc, "to": to_acc, "amount": amount}
                # construir mensaje firmado con 'accion'
                msg = build_signed_action(keys["k_c2s"], "transaccion", payload, keys["key_id"])
                pending.add(msg["nonce"])
                s.sendall((json.dumps(msg) + "\n").encode())

            elif accion == "logout":
                msg = {"accion": "logout"}

            else:
                print("Acción no reconocida.")
                continue

            # enviamos el mensaje
            s.sendall((json.dumps(msg)+ '\n').encode())

            # recibimos respuesta
            resp = s.recv(1024)
            txt = resp.decode()
            ack = json.loads(resp.decode())
            print(f"[Cliente] Respuesta del servidor: {resp.decode()}")
            
            if ack.get("type") == "ack":
                ok, why = verify_ack(keys["k_s2c"], ack, pending, ack_seen, skew_sec=60)
                print("[Cliente] Verificación ACK (1ª):", "OK" if ok else f"ERROR:{why}")

                # ---------- TEST REPLAY CLIENTE ----------
                # Reintentar con el MISMO ACK: debe ser rechazado por Replay
                ok2, why2 = verify_ack(keys["k_s2c"], ack, pending, ack_seen, skew_sec=60)
                print("[Cliente] Verificación ACK (2ª, replay):", "OK" if ok2 else f"ERROR:{why2}")
    # ----------------------------------------

            try:
                obj = json.loads(txt)
            except Exception:
                continue

            if isinstance(obj, dict) and obj.get("type") == "ack":
                body   = {k: obj[k] for k in ("type","status","info","rx_nonce","ts","key_id")}
                mac_rx = b64d(obj.get("mac",""))
                mac_ok = hmac.compare_digest(hmac256(keys["k_s2c"], canon(body)), mac_rx)
                print("[Cliente] Verificación ACK:", "OK" if mac_ok else "MAC INVÁLIDO")


if __name__ == '__main__':
    main()