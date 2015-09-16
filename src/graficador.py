import numpy as np
import matplotlib.pyplot as plt
from collections import Counter

class Graficador:
    """docstring for graficador"""

    def graficar(self, datosX, datosY, labelX, labelY, labels, title):
        #print alfak
        for i,y in enumerate(datosY):
            plt.plot(datosX, y,label=labels[i])

        plt.title(title)
        plt.legend(loc='lower right')
        plt.xlabel(labelX)
        plt.ylabel(labelY)
        fig1 = plt.gcf()
        plt.show()

    def graficar_histograma(self, xticks,datosY, labelX, labelY, labels, title):
        N = len(xticks)
        ind = np.arange(N)
        width = 0.25
        fig, ax = plt.subplots()
        rect1 = ax.bar(ind, datosY, color='r')
        ax.set_ylabel(labelY)
        ax.set_xlabel(labelX)
        ax.set_title(title)
        ax.set_xticks(ind+width)
        xtickNames = ax.set_xticklabels(labels)

        plt.setp(xtickNames, rotation=45, fontsize=10)
        plt.show()
        # plt.savefig(carpeta+"/cantidad"+stringMostrar+".png")

    def graficarProb(self, source):
        """Graficar histogramas probabilidad"""
        occurs = Counter(source)
        largo = len(source)
        # filtro los que aparecen menos de 30
        occurs = {k: (float(v)/float(largo)) for k, v in occurs.iteritems() if v >= 30}
        probs = []
        xlabels = []
        for i in occurs:
            probs.append(occurs[i])
        for ip in occurs:
            xlabels.append(ip)
        self.graficar_histograma(occurs,probs,"ipSrc", "Cantidad",xlabels, "Prob por Ip Src")

    def graficarCant(self, source):
        """Graficar histogramas cantidades"""
        occurs = Counter(source)
        # filtro los que aparecen menos de 30
        occurs = {k: v for k, v in occurs.iteritems() if v >= 30}
        cantidades = []
        for i in occurs:
            cantidades.append(occurs[i])
        xlabels = []
        for ip in occurs:
            xlabels.append(ip)
        self.graficar_histograma(occurs,cantidades,"ipSrc", "Cantidad",xlabels, "Cantidad por Ip Src")

    def graficarEntropias(self, entropia_src,entropia_dst,cant_pkt_arp):
        """ Grafico entropias vs cant_pkt_arp """
        labels = ["EntropiaSrc", "EntropiaDst"]
        self.graficar(cant_pkt_arp, [entropia_src, entropia_dst], "cant_pkt_arp", "entropia_ip_src", labels, "entropia vs arp")
