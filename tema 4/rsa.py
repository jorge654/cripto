from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import gmpy2, os, binascii
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def cifrar(public_key, archivo_plano, archivo_salida):
	archivo = open(archivo_plano, "br")
	contenido = archivo.read()
	archivo.close()
	cifrado = public_key.encrypt(
		contenido, 
		padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
			algorithm = hashes.SHA256(),
			label = None))
	print(cifrado)
	salida = open(archivo_salida, "bw")
	salida.write(cifrado)
	salida.close()


def descifrar(private_key, archivo_plano, archivo_salida):
	archivo = open(archivo_plano, "br")
	contenido = archivo.read()
	archivo.close()
	descifrado = private_key.decrypt(
		contenido,
		padding.OAEP(
			mgf = padding.MGF1(algorithm = hashes.SHA256()),
			algorithm = hashes.SHA256(),
			label = None))
	print(descifrado)
	salida = open(archivo_salida, "bw")
	salida.write(descifrado)
	salida.close()


if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-p", "--Operacion", help="Aplicar operación, cifrar/descifrar")
    all_args.add_argument("-i", "--input", help="Archivo de entrada", required=True)
    all_args.add_argument("-o", "--output", help="Archivo de salida", required=True)
    all_args.add_argument("-l", "--llave", help="Llave", required=True)
    args = vars(all_args.parse_args())

    operacion = args['Operacion']
    archivo_entrada = args["input"]
    archivo_salida = args["output"]

    if operacion == 'cifrar':
    	#Se cifra con la llave publica
    	ruta_public_key = args["llave"]
    	if os.path.exists(ruta_public_key):
    		ruta = open(ruta_public_key, "br")
    		public_key_bytes = ruta.read()
    		ruta.close()
    		#convertimos la llave publica de bytes a un objeto llave
    		try:
    			public_key = serialization.load_pem_public_key(
    				public_key_bytes,
    				backend=default_backend())
    		except Exception as e:
    			print("La llave no pudo ser utilizada, comprueba que la llave que estas pasando sea la correcta")
    			exit()

    		cifrar(public_key, archivo_entrada, archivo_salida)
    	else:
    		print("La ruta con la llave no es la correcta, verificala")
    		exit()
    else:
    	#Se descifra con la llave privada
    	ruta_private_key = args["llave"]
    	if os.path.exists(ruta_private_key):
    		ruta = open(ruta_private_key, "br")
    		private_key_bytes = ruta.read()
    		ruta.close()
    		#Convertimos la llave privada de bytes a un objeto llave
    		try:
    		 	private_key = serialization.load_pem_private_key(
    		 		private_key_bytes, 
    		 		backend=default_backend(),
    		 		password=None)
    		except Exception as e:
    		 	print("La llave no puso ser utilizada, comprueba que la llave que estas pasando sea la correcta")
    		 	exit()

    		descifrar(private_key, archivo_entrada, archivo_salida)

    	else:
    		print("La ruta con la llave no es la correcta, verificala")
    		exit()
