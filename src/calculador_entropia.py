#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
import math

class Simbolo:
    """Símbolo y su probabilidad"""
    def __init__(self, nombre, prob):
        self.nombre = nombre
        self.prob = prob

class Fuente:
    """Fuente que contiene una cadena de simbolos"""
    def __init__(self, simbolos):
        self.simbolos = simbolos

    def entropia(self):
        """calcula entropia de la fuente"""
        entropia = 0
        for s in self.simbolos:
            entropia -= s.prob * math.log(s.prob, 12)
        return entropia

def apariciones_psrc(sniff_data, psrc):
    count = 0
    for d in sniff_data:
        if d.psrc == psrc:
            count +=1
    return count

simbolos = []
sniff_data = sniff(filter="arp", timeout=2)
for d in sniff_data:
    nuevo_simbolo = Simbolo(d.psrc, apariciones_psrc(sniff_data,d.psrc)/len(sniff_data))
    simbolos.append(nuevo_simbolo)

fuente = Fuente(simbolos)
print fuente.entropia()
