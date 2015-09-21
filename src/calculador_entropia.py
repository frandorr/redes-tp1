#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
import math
import csv
from graficador import Graficador

# Fuente S que distingue según tipo
S = []
Ssrc = []
Sdst = []
cant_pkt = 0
cant_arp = 0

# Agrega símbolos a medida que se sniffean.
# La fuente S que distingue tipos
def add_symbol_to_S(pkt):
    global S
    S.append(pkt[Ether].type)

def add_symbol_to_Ssrc(pkt):
    global Ssrc
    global Sdst
    global cant_pkt
    global cant_arp
    cant_pkt+=1
    if ARP in pkt and pkt[ARP].op in (1,2):
        cant_arp+=1
        Ssrc.append(pkt[ARP].psrc)
        Sdst.append(pkt[ARP].pdst)
        res = str(pkt[ARP].hwsrc)+","+ str(pkt[ARP].psrc)+","+ str(pkt[ARP].pdst)+","+ str(pkt[ARP].op)+","+ str(entropy(Ssrc))+","+ str(entropy(Sdst))+ "," + str(cant_arp)+ "," +str(cant_pkt)+"\n"
        with open('facu_src_entropy.txt', 'a') as f:
            f.write(res)
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

# Calcula la probabilidad de un símbolo en la fuente
def prob(source, symbol):
    # dict con ocurrencias de los símbolos en la fuente
    # {"s_0": ocurs_s_0, ..."s_i": occurs_s_i}
    occurs = Counter(source)
    size = len(source)
    prob = float(occurs[symbol])/float(size)
    return

# Función que sniffea red local
def sniff_local(callback_function, intervalo=5, filtro=""):
    """ Escucha pasivamente la red local y procesa los datos en
    la función callback pasada como parámetro durante el intervalo
    de t tiempo en segundos"""
    sniff(prn=callback_function, store=0, timeout=intervalo, filter=filtro)

if __name__ == '__main__':
    graficador = Graficador()
    # Lee csv con datos del experimento
    with open('../results/areatres_src_entropy.txt') as csvfile:
        reader = csv.DictReader(csvfile)
        MACsrc = []
        ip_src = []
        ip_dst = []
        op = []
        entropia_src = []
        entropia_dst = []
        cant_pkt_arp = []
        cant_pkt_total = []
        for row in reader:
            MACsrc.append(row['MACsrc'])
            ip_src.append(row['ip_src'])
            ip_dst.append(row['ip_dst'])
            op.append(row['op'])
            entropia_src.append(row['entropia_src'])
            entropia_dst.append(row['entropia_dst'])
            cant_pkt_arp.append(row['cant_pkt_arp'])
            cant_pkt_total.append(row['cant_pkt_total'])

    # Realiza los gráficos
    graficador.generar_dot(ip_src, ip_dst)
    # graficador.graficarEntropias(MACsrc, MACsrc, cant_pkt_arp)
    # graficador.graficarCant(MACsrc)
    # graficador.graficarProb(MACsrc)
