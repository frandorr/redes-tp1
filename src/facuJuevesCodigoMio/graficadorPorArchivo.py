#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
import math
import sys
import shutil
from collections import Counter
import numpy as np
import matplotlib.pyplot as plt

DictMacSrcCantidad = {}
DictIPDstCantidad = {}
DictIPSrcCantidad = {}
DictMacSrcProbabilidad = {}
DictIPDstProbabilidad = {}
DictIPSrcProbabilidad = {}


#ip dst, ip source, mac source
def ReadFileMakeDict(carpeta,source):
    global DictIPSrcProbabilidad
    global DictIPDstProbabilidad
    global DictMacSrcProbabilidad
    global DictIPSrcCantidad
    global DictMacSrcCantidad
    global DictIPDstCantidad

    archivo = open(carpeta, 'r')

    for line in archivo:
        res = line.split()
        key = res[0]
        value = res[1]
        source[key] = value
    archivo.close()
    return

# Muestra la cantidad de cada uno con su nombre
def mostrarOcurrenciasYCantidades(source, stringMostrar,carpeta):
    occurs = Counter(source)
    largo = len(source)
        # filtro los que aparecen menos de 30
    occurs = {k: (float(v)/float(largo)) for k, v in occurs.iteritems() if v >= 30}
    archivo = open(carpeta + '/'+stringMostrar+'cantidades.txt', 'w')

    for s in occurs:
        print str(stringMostrar) + " "+ str(s) + " con " + str(occurs[s])
        archivo.write(str(s) + " " + str(occurs[s]) + "\n")
    archivo.close()
    return

def graficarPuntual(source,stringMostrar,filtro,queEs):
    listKeys = source.keys()
    cantidadKeys = len(listKeys)
    cantidades = []
    xlabels = []
    for i in range(cantidadKeys):
        key = listKeys[i]
        value = source[key]
        if (float(value) > filtro):
            cantidades.append(float(value))
            xlabels.append(str(key))
    N = len(cantidades)
    ind = np.arange(N)
    width = 0.25 
    fig, ax = plt.subplots()
    rect1 = ax.bar(ind, cantidades, width, color='r')
    ax.set_ylabel(queEs, fontsize=10)
    ax.set_xlabel(stringMostrar, fontsize= 10)
    ax.set_title(queEs + " por " + stringMostrar)
    ax.set_xticks(ind+width)
    xtickNames = ax.set_xticklabels(xlabels)
    plt.setp(xtickNames, rotation=30, fontsize=7)
#    def autolabel(rects):
    # attach some text labels
 #       for rect in rects:
  #          height = rect.get_height()
   #         ax.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%f'%float(height),ha='center', va='bottom')

#    autolabel(rect1)

#    plt.show()
    plt.savefig("v2"+queEs+stringMostrar+str(filtro)+".png")
    return

def graficar(filtroCantidad,filtroProbabilidad):
    graficarPuntual(DictMacSrcCantidad,"Mac Source",filtroCantidad,"Cantidades")
    graficarPuntual(DictIPDstCantidad,"IP Destino",filtroCantidad,"Cantidades")
    graficarPuntual(DictIPSrcCantidad,"IP Source",filtroCantidad,"Cantidades")

    graficarPuntual(DictMacSrcProbabilidad,"Mac Source",filtroProbabilidad,"Probabilidades")
    graficarPuntual(DictIPDstProbabilidad,"IP Destino",filtroProbabilidad,"Probabilidades")
    graficarPuntual(DictIPSrcProbabilidad,"IP Source",filtroProbabilidad,"Probabilidades")
    return

if __name__ == '__main__':

    ReadFileMakeDict("MAC Sourcecantidades.txt",DictMacSrcCantidad)
    ReadFileMakeDict("IP Dstcantidades.txt",DictIPDstCantidad)
    ReadFileMakeDict("IP Sourcecantidades.txt",DictIPSrcCantidad)

    ReadFileMakeDict("MAC Sourceprobabilidad.txt",DictMacSrcProbabilidad)
    ReadFileMakeDict("IP Dstprobabilidad.txt",DictIPDstProbabilidad)
    ReadFileMakeDict("IP Sourceprobabilidad.txt",DictIPSrcProbabilidad)

#    print DictMacSrcCantidad["48:5a:3f:72:f8:0c"] #4
#    print DictIPDstCantidad["66.220.158.2"] #3
#    print DictIPSrcCantidad["10.2.2.254"] #433
#    print DictMacSrcProbabilidad["48:5a:3f:72:f8:0c"] #0.000444543231829
#    print DictIPDstProbabilidad["66.220.158.2"] #0.000333407423872
#    print DictIPSrcProbabilidad["10.2.2.254"] #0.0481218048455

    graficar(500,0.02)
    graficar(100,0.02)


