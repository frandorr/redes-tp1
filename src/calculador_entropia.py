#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
import math
import sys
from collections import Counter

# Fuente S que distingue según tipo
S = []
ListaMacDst = []
ListaMacSrc = []
ListaIPDst = []
ListaIPSrc = []
cantidadPaquetesARP = 0
cantidadPaquetes = 0
# Agrega símbolos a medida que se sniffean.
# La fuente S que distingue tipos
def add_symbol_to_S(pkt):
    global S
    global cantidadPaquetesARP
    global cantidadPaquetes
#    print "---"
#    print pkt.src
#    print pkt.dst
    if "Ether" in pkt:
        S.append(pkt[Ether].type)
        if ARP in pkt:
            cantidadPaquetesARP = cantidadPaquetesARP + 1
#            print "es ARP"
        cantidadPaquetes = cantidadPaquetes + 1
#    else:
#        print "No es ARP"
def add_symbol_to_host(pkt):
    global ListaSrc
    global ListaDst
 #   print "es arp con filter!"
#    print "---"
#    print pkt.src
#    print pkt.dst
    if "Ether" in pkt:
#        print "es arp con filter y ether!"
        ListaMacSrc.append(pkt[Ether].src) #mac src
        ListaMacDst.append(pkt[Ether].dst) #mac dst

        ListaIPSrc.append(pkt[Ether].psrc) #IP src
        ListaIPDst.append(pkt[Ether].pdst) #IP dst

#    pkt.show()
#    print "un arp!!!" 

#Muestra simbolo y probabilidad
def mostrarSimboloYProbabilidad(source,stringMostrar,carpeta):
    occurs = Counter(source)
    size = len(source)
    probs = []

    archivo = open(carpeta + '/'+stringMostrar+'probabilidad.txt', 'w')

    for s in occurs:
        prob = float(occurs[s])/float(size)
        print str(stringMostrar) + " "+ str(s) + " con probabilidad " + str(prob)
        archivo.write(str(s) + " " + str(prob) + "\n")
#        probs.append(prob)
    archivo.close()

  #  acum = 0
 #   for i in probs:
#        print i
 #       acum = acum + i
 #   print "probabilidad final sumada" + str(acum)
    return

# Muestra la cantidad de cada uno con su nombre
def mostrarOcurrenciasYCantidades(source, stringMostrar,carpeta):
    occurs = Counter(source)

    archivo = open(carpeta + '/'+stringMostrar+'cantidades.txt', 'w')

    for s in occurs:
        print str(stringMostrar) + " "+ str(s) + " con " + str(occurs[s])
        archivo.write(str(s) + " " + str(occurs[s]) + "\n")
    archivo.close()
    return
# Calcula la entropia de una fuente dada como una lista de simbolos
def entropy(source):
    entropy = 0.0
    # dict con ocurrencias de los símbolos en la fuente
    # {"s_0": ocurs_s_0, ..."s_i": occurs_s_i}
    occurs = Counter(source)
    size = len(source)
    for s in occurs:
        prob = float(occurs[s])/float(size)
        entropy -= prob * math.log(prob, 2)
    return entropy

# Muestra datos ether
def show_ether(pkt):
    print pkt[Ether].src, pkt[Ether].dst, pkt[Ether].type

# Función que sniffea red local
def sniff_local(callback_function,bloqueado, intervalo):
    """ Escucha pasivamente la red local y procesa los datos en
    la función callback pasada como parámetro durante el intervalo
    de t tiempo en segundos"""
    if (bloqueado):
        sniff(prn=callback_function, store=0, timeout=intervalo)    
    else:
        sniff(prn=callback_function, store=0, timeout=intervalo, filter="arp")

if __name__ == '__main__':
    intervalo = float(sys.argv[1])
    veces = float(sys.argv[2])
    i = 0
    while (i<veces):
        carpeta = "./experimento" + str(i)
        os.makedirs(carpeta)
        sniff_local(add_symbol_to_S,True,intervalo)
        print "paquetes ARP " + str(cantidadPaquetesARP)
        print "paquetes " + str(cantidadPaquetes)

        archivo = open(carpeta + '/cantidadPaquetesARP.txt', 'w')
        archivo.write(str(cantidadPaquetesARP))
        archivo.close()

        archivo = open(carpeta + '/cantidadPaquetes.txt', 'w')
        archivo.write(str(cantidadPaquetes))
        archivo.close()

        sniff_local(add_symbol_to_host,False,intervalo)

        print "Tipos"
        print "entropia type" + str(entropy(S))

        archivo = open(carpeta + '/entropiaTipo.txt', 'w')
        archivo.write(str(entropy(S)))
        archivo.close()

        mostrarOcurrenciasYCantidades(S,"Protocolo",carpeta)
        mostrarSimboloYProbabilidad(S,"Protocolo",carpeta)

        print "Lista MAC SRC"
        print "entropia mac src " + str(entropy(ListaMacSrc))

        archivo = open(carpeta + '/entropiaMacSrc.txt', 'w')
        archivo.write(str(entropy(ListaMacSrc)))
        archivo.close()

        mostrarOcurrenciasYCantidades(ListaMacSrc, "MAC Source",carpeta)
        mostrarSimboloYProbabilidad(ListaMacSrc,"MAC Source",carpeta)

        print "Lista MAC DST"
        print "entropia mac dst " + str(entropy(ListaMacDst))

        archivo = open(carpeta + '/entropiaMacDst.txt', 'w')
        archivo.write(str(entropy(ListaMacDst)))
        archivo.close()

        mostrarOcurrenciasYCantidades(ListaMacDst, "MAC Dst",carpeta)
        mostrarSimboloYProbabilidad(ListaMacDst,"MAC Dst",carpeta)

        print "Lista IP SRC"
        print "entropia IP SRC " + str(entropy(ListaIPSrc))

        archivo = open(carpeta + '/entropiaIPSrc.txt', 'w')
        archivo.write(str(entropy(ListaIPSrc)))
        archivo.close()

        mostrarOcurrenciasYCantidades(ListaIPSrc, "IP Source",carpeta)
        mostrarSimboloYProbabilidad(ListaIPSrc,"IP Source",carpeta)

        print "Lista IP DST"
        print "entropia IP dst " + str(entropy(ListaIPDst))


        archivo = open(carpeta + '/entropiaIPDst.txt', 'w')
        archivo.write(str(entropy(ListaIPDst)))
        archivo.close()

        mostrarOcurrenciasYCantidades(ListaIPDst, "IP Dst",carpeta)
        mostrarSimboloYProbabilidad(ListaIPDst,"IP Dst",carpeta)

        i = i + 1
