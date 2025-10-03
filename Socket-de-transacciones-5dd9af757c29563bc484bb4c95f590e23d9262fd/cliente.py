import socket
import json
import secure_utils
import hashlib
import getpass
HOST = '127.0.0.1' #Dirección del servidor
PORT = 11002 #puerto del servidor

#Lo mas sucio que he hecho en mi vida para guardar la contraseña para usarla en el calculo de la hmac
#me avergüenza pero no he sabido hacerlo de otra manera, de todas formas es volatil y no corre riesgo ninguno ya que no se
#compartirá con nadie ya que está en local. Lo siento mucho :-)
passwd = []

def main():
    #creamos el socket TCP (IPv4, stream) y lo abrimos para que se cierre automáticamente al acabar
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        # conectamos con el servidor
        s.connect((HOST,PORT))

        print("[Cliente] Conectado al servidor")

        # ---Bucle para realizar multiples acciones---
        while True:
            accion = input("Acción (1.register/2.login/3.transaccion/4.logout/5.salir): ") #Pedimos la acción a realizar

            #Salir del bucle
            if accion == "5":
                print("[Cliente] Cerrando conexión...")
                break

            #Registro del usuario
            if accion == "1":
                username = input("Nuevo usuario: ") #Pedimos el usuario
                password = getpass.getpass("Contraseña: ") #input("Contraseña: ") #Pedimos la contraseña
                msg = {"accion": "register", "username": username, "password": password} 

            #Login del usuario
            elif accion == "2":
                username = input("Usuario: ") #Pedimos el usuario
                password = getpass.getpass("Contraseña: ") #Pedimos la contraseña
                passwd = [] #Limpiamos la lista por si acaso (Por dios que vergüenza)
                passwd.append(password) #Guardamos la contraseña en la lista para usarla luego en el cálculo del hmac
                msg = {"accion": "login", "username": username, "password": password}

            elif accion == "3":
                #1º pedimos nonce
                msg = {"accion":"pet_transaccion"}
                s.sendall((json.dumps(msg)+ '\n').encode()) #Mandamos la petición

                #2º nos lo envia el servidor
                resp = s.recv(1024).decode()
                resp = json.loads(resp)

                #Vemos si está todo bien
                status = resp.get("status")

                #Si es así, es decir que estamos logeado, seguimos
                if status == "OK":
                    #reconocemos el nonce que nos manda el servidor
                    nonce = resp.get("nonce")

                    #creamos el mensaje
                    data = input("Introduce transacción (CuentaOrigen,CuentaDestino,Cantidad): ")

                    #sacamos la contraseña, perdon por ser tan bruto para esto
                    key = passwd[0]

                    #le sacamos el hash porque es lo que tiene el servidor
                    key = hashlib.sha256(key.encode()).hexdigest()

                    #calculamos el hmac
                    mac = secure_utils.calcula_hmac(key,data, nonce)

                    #mandamos petición de transacción
                    msg = {"accion": "transaccion", "data": data, "mac":mac}

            #Logout del usuario
            elif accion =="4":
                passwd = [] #Si hay deslogueo, limpiamos la lista de la contraseña
                msg = {"accion": "logout"}

            else:
                print("Acción no reconocida.")
                continue
            
            # enviamos el mensaje
            s.sendall((json.dumps(msg)+ '\n').encode())

            # recibimos respuesta
            resp = s.recv(1024)
            print(f"[Cliente] Respuesta del servidor: {resp.decode()}")

if __name__ == '__main__':
    main()