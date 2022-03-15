"""
Cifrado AES CTR
"""
import argparse
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def calcular_xor(binario1, binario2):
    'Calcular xor de dos cadenas'

    bytes1 = list(binario1)
    bytes2 = list(binario2)

    longitud_menor = len(bytes1)
    lista_mas_larga = bytes2
    if len(bytes2) < longitud_menor:
        longitud_menor = len(bytes2)
        lista_mas_larga = bytes1

    res_bytes = []

    for i in range(longitud_menor):
        res_bytes.append(bytes1[i] ^ bytes2[i])
    return bytes(res_bytes) + bytes(lista_mas_larga[longitud_menor:])

def ataque(mensaje_cifrado, cabecera):
    cabecera_cifrada = mensaje_cifrado[:len(cabecera)]
    print(cabecera_cifrada)
    key_stream = calcular_xor(cabecera_cifrada, cabecera)
    return key_stream

def cifrar_key_stream(cabecera_atacante, key_stream):
    texto_atacante = calcular_xor(cabecera_atacante, key_stream)
    print(texto_atacante)
    return texto_atacante

def remplazar_texto(cabecera_falsa, texto_cifrado):
    texto_cifrado_sc = texto_cifrado[len(cabecera_falsa):]
    cifrado_atacado = cabecera_falsa+texto_cifrado_sc
    return cifrado_atacado



if __name__ == '__main__':
    cabecera_conocida = b'''<XML>
  <CredictCardPurchase>
    <Merchant>Acme Inc</Merchant>
'''

    mi_cadena_maleada = b'''<XML>
  <CredictCardPurchase>
    <Merchant>Jogb Uuv</Merchant>
'''
    print(len(cabecera_conocida))
    print(len(mi_cadena_maleada))
    file = open("atacante.xml.cif", "br")
    contenido = file.read()
    #print(len(contenido))
    key_stream = ataque(contenido, cabecera_conocida)
    #print("==============key stream ==========")
    #print(key_stream)
    #print(len(key_stream))

    cabecera_cifrada = cifrar_key_stream(mi_cadena_maleada, key_stream)
    #print("=============cabecera cifrada=========")
    #print(cabecera_cifrada)
    #print(len(cabecera_cifrada))

    texto_atacado = remplazar_texto(cabecera_cifrada, contenido)
    #print("=================texto atacado ==========")
    #print(texto_atacado)
    #print(len(texto_atacado))

    archivo = open("archivo_atacado.xml.cif", "bw")
    archivo.write(texto_atacado)
    archivo.close()
    print(len(contenido))
    print(len(texto_atacado))
