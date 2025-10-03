import json
import hashlib
import os
class UserManager():
    # en la función princiapl se pasa un archivo donde se va a almacenar
    # los archivos
    def __init__(self,users_file = "user.json"):
        self.users_file = users_file # inicializamos el atributo donde se registra el server
        self.users = self._load_user() # llamamos a la función privada que carga al usuario
        # para una gestión más eficiente de los errores
        # si no hay usuarios, creamos el por defecto
        if not self.users:
            # llamamos a la función privada que crea el usuario
            self._create_default_user()
    # función que carga los usuarios desde un archivo JSON
    def _load_user(self):
        # Aquí se carga los usuarios
        # Para gestionar mejor los errores con try y catch
        try:
            if os.path.exists(self.users_file):
                # abrimos el archivo para leer
                with open(self.users_file,'r') as f :
                    # devolvemos el archivo .json en un diccionario
                    return json.load(f)
        except Exception as e :
            print(f'Error cargando usuarios!!! : {e}')
            # devolvemos un diccionario vacio
            return {}
  # Esta función se ejecutará solo una vez para cargar usuarios al sistema
  # y cumplir con el requisito "Una lista de usuarios pre-registrados Sin transacciones realizadas previamente"
    def _create_default_user(self):
        #creación del usuario por defecto
        # en un formato JSON
        default_users = {
            "admin": self._hash_password("admin123"),
            "usuario" : self._hash_password("Cop3r/nic0"),
            "cliente1" : self._hash_password("Ed/Sh33ran")
        }
        # asignamos al atribto users el valor de la variable default_users
        self.users = default_users
        self._save_users()
        print("Hemos cargado los usuarios por defecto")
        pass
    def _hash_password(self,pswd):
        # vamos crear un resumen  de la contraseña codificada y con hash en heexadecimal
        return hashlib.sha256(pswd.encode()).hexdigest()
    def _get_hash_de(self, usuario):
        """
        Devuelve el hash de la contraseña del usuario dado.
        Si el usuario no existe, devuelve None.
        """
        return self.users.get(usuario, None)
    def _save_users(self):
        # Función para guardar el usuario
        try:
            # abrimos el archivo para escribir
            with open(self.users_file,'w') as f :
                    # vertemos el contenoido en formato json en el archivo a escribir
                    json.dump(self.users, f, indent=2)
            # devolvemos True porque se ha realizado la acción
            return True
        except Exception as e :
            # mensaje de error por fallo
            print(f'Error cargando usuarios!!! : {e}')
            # devolvemso False
            return False
    # Esta función se pude llamar desde el servidor
    def register_user(self, username, password):
        # Función para registrar usuarios
        # devuelve si se se ha completado exitosamente la acción
        # y un mensaje

        # comprobamos que este usuario que estamos creando no está ya registrado
        if username in self.users:
            #print("El usuario ya existe")
            return False, "El usuario ya existe"
        # Verificación de condiciones de seguridad
        if len(username) <3 or len(password) <4 :
            #print("No se cumple los requisitos para la contraseña")
            return False, "No se cumple los requisitos para la contraseña"

        # Una vez cumplido los requisitos preliminares
        # procedemos a crear al usuario y guardarli
        self.users[username] = self._hash_password(password) # guaradamos los datps correctamente en el diccionario
        # procedemos a guardar al usuario
        if self._save_users():
            #print("Usuario guradado correctamente")
            return True, "Usuario guradado correctamente"
        else:
            #print("Usuario no se ha podido guardar")
            return False, "Usuario no se ha podido guardar"

    # Esta función es para verficar las credenciales del usuario
    # También puede ser llamado desde el servidor

    def verify_credenciales(self, username, pswd):
        # verificar las credenciales del usuario
        if username not in self.users:
            #verificamos que el usuario está ya registrado
            #print("Usuario  no encontrado")
            return False, "Usuario  no encontrado"
        hash_pswd = self._hash_password(pswd)
        # verificamos que la contraseña es la correcta
        if self.users[username] == hash_pswd:
            # la contraseña es correcta
            #print("Contraseña correcta")
            return True, "password correcto"
        else:
            # contraseña incorrecta
            #print("Contraseña Incorrecta")
            return False, "password incorrecto"

    #def user_exists(self, username):
    #    return username in self.users
    #def list_users(self):
    #    return list(self.users.keys()):
    # función para eliminar usuarios, no es obligatoria
    # puede ser util en caso de fallos
    def delete_user(self, username):
        if username in self.users:
            del self.users[username]
            if self._save_users():
                #print("Usuario eliminado correctamente")
                return True, "Usuario eliminado correctamente"
            else:
                #print("Usuario no se ha podido eliminar")
                return False, "Usuario no se ha podido eliminar"

if __name__ == "__main__":
    print("=== PRUEBA INDEPENDIENTE DE UsersManager ===\n")

    # Crear instancia
   # esto se hizo para probar 
   # manager = UserManager()
   # manager.register_user("nuevo_user", "nueva_pass123")
   # manager.verify_credenciales("admin", "admin123")