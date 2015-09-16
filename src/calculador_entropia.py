#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
import math
import sys
import shutil
from collections import Counter
import numpy as np
import matplotlib.pyplot as plt

# Fuente S que distingue según tipo
S = []
ListaMacDst = []
ListaMacSrc = []
ListaIPDst = []
ListaIPSrc = []

entropiaS = []
entropiaMacDst = []
entropiaMacSrc = []
entropiaIPDst = []
entropiaIPSrc = []

cantidadPaquetesARP = 0
cantidadPaquetes = 0

iptype = []
mactype = []

ipnodos = []
macnodos = []

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
            if (iptype.count(str(pkt[Ether].psrc) + " -> " + str(pkt[Ether].pdst)) == 0):
                archivo = open(carpeta + '/IPtype.txt', 'a')
                archivo.write(str(pkt[Ether].psrc) + " -> " + str(pkt[Ether].pdst) + ";\n")
                iptype.append(str(pkt[Ether].psrc) + " -> " + str(pkt[Ether].pdst))
                archivo.close()
        if (mactype.count(str(pkt[Ether].src) + " -> " + str(pkt[Ether].dst)) == 0):
            archivo = open(carpeta + '/MACtype.txt', 'a')
            archivo.write(str(pkt[Ether].src) + " -> " + str(pkt[Ether].dst) + ";\n")
            mactype.append(str(pkt[Ether].src) + " -> " + str(pkt[Ether].dst))
            archivo.close()
#            print "es ARP"
        cantidadPaquetes = cantidadPaquetes + 1
#    else:
#        print "No es ARP"
    archivo = open(carpeta + '/entropiaContinuaType.txt', 'a')
    archivo.write(str(entropy(S)) + "\n")
    entropiaS.append(entropy(S))
    archivo.close()

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

        archivo = open(carpeta + '/entropiaContinuaMACsrc.txt', 'a')
        archivo.write(str(entropy(ListaMacSrc)) + "\n")
        entropiaMacSrc.append(entropy(ListaMacSrc))
        archivo.close()

        archivo = open(carpeta + '/entropiaContinuaMACdst.txt', 'a')
        archivo.write(str(entropy(ListaMacDst)) + "\n")
        entropiaMacDst.append(entropy(ListaMacDst))
        archivo.close()

        archivo = open(carpeta + '/entropiaContinuaIPsrc.txt', 'a')
        archivo.write(str(entropy(ListaIPSrc)) + "\n")
        entropiaIPSrc.append(entropy(ListaIPSrc))
        archivo.close()

        archivo = open(carpeta + '/entropiaContinuaIPdst.txt', 'a')
        archivo.write(str(entropy(ListaIPDst)) + "\n")
        entropiaIPDst.append(entropy(ListaIPDst))
        archivo.close()

        if(macnodos.count(str(pkt[Ether].src) + " -> " + str(pkt[Ether].dst)) == 0):
            archivo = open(carpeta + '/MACnodos.txt', 'a')
            archivo.write(str(pkt[Ether].src) + " -> " + str(pkt[Ether].dst) + ";\n")
            macnodos.append(str(pkt[Ether].src) + " -> " + str(pkt[Ether].dst))
            archivo.close()

        if(ipnodos.count(str(pkt[Ether].psrc) + " -> " + str(pkt[Ether].pdst)) == 0):
            archivo = open(carpeta + '/IPnodos.txt', 'a')
            archivo.write(str(pkt[Ether].psrc) + " -> " + str(pkt[Ether].pdst) + ";\n")
            ipnodos.append(str(pkt[Ether].psrc) + " -> " + str(pkt[Ether].pdst))
            archivo.close()

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

def graficarCantidad(source,stringMostrar,carpeta):
    print "graficar cantidad"
    occurs = Counter(source)
    N = len(occurs)
    ind = np.arange(N)
    cantidades = []
    xlabels = []
    for s in occurs:
#        print str(stringMostrar) + " "+ str(s) + " con " + str(occurs[s])
        cantidades.append(occurs[s])
        xlabels.append(s)
    print cantidades
    width = 0.25 
    fig, ax = plt.subplots()
    rect1 = ax.bar(ind, cantidades, width, color='r')
    ax.set_ylabel('Cantidades')
    ax.set_xlabel(stringMostrar)
    ax.set_title("Cantidades por " + stringMostrar)
    ax.set_xticks(ind+width)
    ax.set_xticklabels(xlabels)

    def autolabel(rects):
    # attach some text labels
        for rect in rects:
            height = rect.get_height()
            ax.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%d'%int(height),ha='center', va='bottom')

    autolabel(rect1)

#    plt.show()
    plt.savefig(carpeta+"/cantidad"+stringMostrar+".png")
    return

def graficarProbabilidad(source,stringMostrar,carpeta):
    print "graficar probabilidad"

    occurs = Counter(source)
    N = len(occurs)
    size = len(source)
    probs = []
    ind = np.arange(N)
    xlabels = []
    for s in occurs:
        prob = float(occurs[s])/float(size)
#        print str(stringMostrar) + " "+ str(s) + " con probabilidad " + str(prob)
        probs.append(prob)
        xlabels.append(s)
    print probs
    width = 0.25 
    fig, ax = plt.subplots()
    rect1 = ax.bar(ind, probs, width, color='r')
    ax.set_ylabel('Probabilidades')
    ax.set_ylim((0,1))
    ax.set_xlabel(stringMostrar)
    ax.set_title("Probabilidades por " + stringMostrar)
    ax.set_xticks(ind+width)
    ax.set_xticklabels(xlabels)

    def autolabel(rects):
    # attach some text labels
        for rect in rects:
            height = rect.get_height()
            ax.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%f'%float(height),ha='center', va='bottom')

    autolabel(rect1)

#    plt.show()
    plt.savefig(carpeta+"/probabilidad"+stringMostrar+".png")
    return
def graficarCantidades(carpeta):
    graficarCantidad(S,"Protocolo",carpeta)
    graficarCantidad(ListaMacSrc,"Mac Source",carpeta)
    graficarCantidad(ListaMacDst,"Mac Dst",carpeta)
    graficarCantidad(ListaIPSrc,"IP Source",carpeta)
    graficarCantidad(ListaIPDst,"IP Dst",carpeta)
    return

def graficarProbabilidades(carpeta):
    graficarProbabilidad(S,"Protocolo",carpeta)
    graficarProbabilidad(ListaMacSrc,"Mac Source",carpeta)
    graficarProbabilidad(ListaMacDst,"Mac Dst",carpeta)
    graficarProbabilidad(ListaIPSrc,"IP Source",carpeta)
    graficarProbabilidad(ListaIPDst,"IP Dst",carpeta)
    return


def graficarEntropiaDstVsSrc(dst,src,stringdst,stringsrc,carpeta):
    #print alfak
    tam = len(dst)
    xs = np.arange(0, tam,1)
    plt.plot(xs, src,label=stringsrc)
    plt.plot(xs, dst,label=stringdst)

    plt.title("Comparar la entropia de las fuentes a medida que crece la cantidad")
    plt.legend(loc='lower right')
    plt.xlabel('Cantidad')
    plt.ylabel('Entropia')
    fig1 = plt.gcf()
#    plt.show()
    plt.savefig(carpeta+"/entropia"+stringdst+"y"+stringsrc+".png")
    return
def graficarUnaEntropia(data,string,carpeta):
    #print alfak
    tam = len(data)
    xs = np.arange(0, tam,1)
    plt.plot(xs, data,label=string)

    plt.title("Entropia en funcion de la cantidad")
    plt.legend(loc='lower right')
    plt.xlabel('Cantidad')
    plt.ylabel('Entropia')
    fig1 = plt.gcf()
#    plt.show()
    plt.savefig(carpeta+"/entropia"+string+".png")

    return

def graficarEntropias(carpeta):
    graficarUnaEntropia(entropiaS,"Protocolo",carpeta)
    graficarEntropiaDstVsSrc(entropiaIPDst,entropiaIPSrc,"IP Dst","IP Source",carpeta)
    graficarEntropiaDstVsSrc(entropiaMacDst,entropiaMacSrc,"Mac Dst","Mac Source",carpeta)
    return

def graficar(carpeta):
#    graficarCantidades(carpeta)
 #   graficarProbabilidades(carpeta)
    graficarEntropias(carpeta)
    return
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
        shutil.rmtree(carpeta, ignore_errors=True)
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

        graficar(carpeta)

        #no deberia borrar todas las variables globales aca?
        S = []
        ListaMacDst = []
        ListaMacSrc = []
        ListaIPDst = []
        ListaIPSrc = []
        cantidadPaquetesARP = 0
        cantidadPaquetes = 0

