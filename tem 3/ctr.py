"""
Cifrado AES CTR
"""

import argparse
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def cifrar(path_entrada, path_salida, key, iv):
	aesCipher = Cipher(algorithms.AES(key),
						modes.CTR(iv),
						backend = default_backend)
	aesEncryptor = aesCipher.encryptor()
	salida = open(path_salida, "wb")
	for buffer in open(path_entrada, "rb"):
		cifrado = aesEncryptor.update(buffer)
		salida.write(cifrado)
	aesEncryptor.finalize()
	salida.close()


def descifrar(path_entrada, path_salida, key, iv):
	aesCipher = Cipher(algorithms.AES(key),
						modes.CTR(iv),
						backend = default_backend)
	aesDecryptor = aesCipher.decryptor()
	salida = open(path_salida, "wb")
	descifrar = b""
	for buffer in open(path_entrada, "rb"):
		descifrar = aesDecryptor.update(buffer)
		salida.write(descifrar)
	aesDecryptor.finalize()
	salida.close()


if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-p", "--Operacion", help="Aplicar operación, cifrar/descifrar")
    all_args.add_argument("-i", "--input", help="Archivo de entrada", required=True)
    all_args.add_argument("-o", "--output", help="Archivo de salida", required=True)
    all_args.add_argument("-l", "--llave", help="Llave", required=True)
    all_args.add_argument("-v", "--vector", help="Vector de Inicialización", required=True)
    args = vars(all_args.parse_args())
    operacion = args['Operacion']

    # Preparar llave recibida en base64
    llave = base64.b64decode(args['llave'])
    if len(llave) != 16:
        print('La llave de entrada debe ser de 16 bytes')
        exit()
    vector = base64.b64decode(args['vector'])

    if len(vector) != 16:
   		print('El vector de Inicialización debe de ser de 16 bytes')
  
    if operacion == 'cifrar':
        cifrar(args['input'], args['output'], llave, vector)
    else:
        descifrar(args['input'], args['output'], llave, vector)
