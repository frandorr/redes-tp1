#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
from graficador import Graficador

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
    # graficador.graficarEntropias(ip_src, ip_dst, cant_pkt_arp)
    graficador.graficarInformacion(ip_src)
    graficador.graficarProb(ip_src)
