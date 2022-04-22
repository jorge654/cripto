"""
Servidor.

Receptor del protocolo agree upon transmission para el intercambio de un mensaje protegido
"""

import sys 
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import llaves

def crear_socket(puerto):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(('', int(puerto)))
    return servidor



def escuchar(servidor):
    servidor.listen(5)
    cliente, _ = servidor.accept()
    mensaje = cliente.recv(1024)
    cliente.close()
    return mensaje

def descifrar_llaves(llaves_cifradas, llave_privada):
    recovered1 = llave_privada.decrypt(
        llaves_cifradas,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None))
    aes = recovered1[:16]
    iv = recovered1[16:32]
    mac = recovered1[-128:]
    return aes, iv, mac

def verificar_firma(aes, iv, mac, firma, llave_publica):
    mensaje = aes + iv + mac
    try:
        llave_publica.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except:
        return False
    
    
def calcular_HMAC(binario, mac):
    codigo = hmac.HMAC(mac, hashes.SHA256(), backend = default_backend())
    codigo.update(binario)
    return codigo.finalize()


def descifrar_mensaje(aes, iv, mensaje_cifrado):
    aesCipher = Cipher(algorithms.AES(aes),
                       modes.CTR(iv),
                       backend = default_backend)
    aesDecryptor = aesCipher.decryptor()
    plano = aesDecryptor.update(mensaje_cifrado)
    aesDecryptor.finalize()
    return plano

if __name__ == '__main__':
    servidor = crear_socket(sys.argv[1])
    llave_privada_path = sys.argv[2]
    llave_privada = llaves.recuperar_privada_from_path(llave_privada_path)
    llave_publica_emisor_path = sys.argv[3]
    llave_publica_emisor = llaves.recuperar_publica_from_path(llave_publica_emisor_path)
    
    print('Escuchando...')
    mensaje_recibido = escuchar(servidor)
    
    #División de las llaves
    llaves_cifradas = mensaje_recibido[:256]
    
    firma = mensaje_recibido[len(llaves_cifradas):512]
    
    mensaje_cifrado = mensaje_recibido[512:len(mensaje_recibido)-32]
    
    codigo_mac = mensaje_recibido[-32:]
    
    #descifrar llaves para utilizarlas después
    aes, iv, mac = descifrar_llaves(llaves_cifradas, llave_privada)
    
    
    #proceso de verificación de los elementos de seguridad    
    if verificar_firma(aes, iv, mac, firma, llave_publica_emisor):
        if codigo_mac == calcular_HMAC(llaves_cifradas + firma + mensaje_cifrado, mac):
            print('El mensaje ultrasecreto es :D')
            mensaje_descifrado = descifrar_mensaje(aes, iv, mensaje_cifrado)
            print(mensaje_descifrado.decode('utf-8'))
        else:
            print('La llave MAC es erronea >:v ')
    else:
        print('La firma es erronea :c')
