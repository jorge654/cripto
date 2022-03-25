from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import gmpy2, os, binascii
import argparse


def guardar_archivo(ruta, contenido, nombre_archivo):
	if not os.path.exists(ruta):
		os.mkdir(ruta)
	f = open(ruta+"/"+nombre_archivo+".pem", "bw")
	f.write(contenido)
	f.close()



def generar_privada(ruta):
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend())
	# Convertir llave privada a bytes, sin cifrar los bytes
	private_key_bytes = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption())
	#print(private_key_bytes)

	# Convertir la llave privada de bytes a objeto llave
	# Como no se cifraron los bytes no hace falta un password
	#private_key = serialization.load_pem_private_key(
		#private_key_bytes,
		#backend=default_backend(),
		#password=None)
	#print(private_key_pem)
	guardar_archivo(ruta, private_key_bytes, "privada")
	return private_key


def generar_publica(ruta, private_key):
	# Extraer llave publica de llave privada
	public_key = private_key.public_key()

	#convertimos la llave publica en bytes
	public_key_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)

	guardar_archivo(ruta, public_key_bytes, "publica")
	return public_key



if __name__ == '__main__':
	all_args = argparse.ArgumentParser()
	all_args.add_argument("-p", "--private", help="Ruta salida llave privada", required=True)
	all_args.add_argument("-s", "--public", help="Ruta salida llave publica", required=True)
	args = vars(all_args.parse_args())
	ruta_privada = args["private"]
	ruta_publica = args["public"]
	private_key = generar_privada(ruta_privada)
	public_key = generar_publica(ruta_publica, private_key)
	print("Sus llaves han sido creadas con éxito")
