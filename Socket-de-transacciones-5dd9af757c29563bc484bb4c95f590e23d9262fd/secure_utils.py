import hashlib
import hmac
import os

def genera_nonce(tamano=16):
    #Genera un nonce aleatorio en hexadecimal
    return os.urandom(tamano).hex()

def calcula_hmac(key,mensaje,nonce):
    #Calcula el hmac
    key_bytes = bytes.fromhex(key) #Hash de hex -> bytes
    mensaje_bytes = (mensaje+nonce).encode() # encode() convierte string concatenado en bytes porque hmac trabaja sobre bytes
    mac = hmac.new(key_bytes, mensaje_bytes, hashlib.sha256).hexdigest()
    return mac

def verifica_hmac(hmac_in, key, mensaje, nonce):
    #Verifica hmac para integridad del mensaje
    hmac_esperado=calcula_hmac(key, mensaje, nonce)
    return hmac.compare_digest(hmac_esperado,hmac_in)
