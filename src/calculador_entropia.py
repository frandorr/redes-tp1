#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
import math
from collections import Counter

# Fuente S que distingue según tipo
S = []

# Agrega símbolos a medida que se sniffean.
# La fuente S que distingue tipos
def add_symbol_to_S(pkt):
    global S
    S.append(pkt[Ether].type)

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
def sniff_local(callback_function, intervalo=5):
    """ Escucha pasivamente la red local y procesa los datos en
    la función callback pasada como parámetro durante el intervalo
    de t tiempo en segundos"""
    sniff(prn=callback_function, store=0, timeout=intervalo)

if __name__ == '__main__':
    sniff_local(add_symbol_to_S)
    print entropy(S)
