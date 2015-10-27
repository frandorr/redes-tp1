import numpy as np
import math
import matplotlib.pyplot as plt
from collections import Counter
import operator
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

    def graficar_histograma(self, xticks,datosY, labelX, labelY, labels, title, entropia=0):
        N = len(xticks)
        unArr = (N+1)*[entropia]
        ind = np.arange(N)
        width = 0.25
        fig, ax = plt.subplots()
        rect1 = ax.bar(ind, datosY, color='r')
        ax.plot(unArr, "k--")
        ax.set_ylabel(labelY)
        ax.set_xlabel(labelX)
        ax.set_title(title)
        ax.set_xticks(ind+width)
        xtickNames = ax.set_xticklabels(labels)
        plt.yscale('log')
        plt.setp(xtickNames, rotation=45, fontsize=10)
        plt.show()
        # plt.savefig(labelX+labelY+.png")

    def graficarProb(self, source):
        """Graficar histogramas probabilidad"""
        occurs = Counter(source)
        largo = len(source)
        # filtro los que aparecen menos de 30
        occurs = {k: (float(v)/float(largo)) for k, v in occurs.items() if v >= 50}
        probs = []
        xlabels = []
        for i in occurs:
            probs.append(occurs[i])
        for ip in occurs:
            xlabels.append(ip)
        occurs = sorted(occurs.items(), key=operator.itemgetter(1))
        probs = sorted(probs)
        self.graficar_histograma(occurs,probs,"IP Source", "Probabilidad",xlabels, "Probabilidades por IP Source")

    def graficarCant(self, source):
        """Graficar histogramas cantidades"""
        occurs = Counter(source)
        # filtro los que aparecen menos de 30
        occurs = {k: v for k, v in occurs.items() if v >= 50}
        cantidades = []
        for i in occurs:
            cantidades.append(occurs[i])
        xlabels = []
        for ip in occurs:
            xlabels.append(ip)
        occurs = sorted(occurs.items(), key=operator.itemgetter(1))
        cantidades = sorted(cantidades)
        self.graficar_histograma(occurs,cantidades,"MAC Source", "Cantidad",xlabels, "Cantidad por MAC Source")


    def graficarInformacion(self, source):
        """Graficar histogramas cantidades"""
        occurs = Counter(source)
        print(source)
        # filtro los que aparecen menos de 30
        occurs = {k: v for k, v in occurs.items()}
        largo = sum(occurs.values())
        occurs = {k: (float(v)/float(largo)) for k, v in occurs.items()}

        infos = []
        occurs = sorted(occurs.items(), key=operator.itemgetter(1))[::-1]
        print(occurs)
        xlabels = []
        entropia = 0
        total = 0
        for (i,j) in occurs:
            prob = j
            total+=prob
            info = prob*math.log(1/prob)/math.log(2)
            print("Info:", info)
            entropia += info
            infos.append(math.log(1/prob)/math.log(2))
            xlabels.append(i)
        print("Entropia: ",entropia)
        print("Total: ", total)
        print(occurs)
        print(infos[::-1])
        self.graficar_histograma(occurs,infos,"IP Source", "Información",xlabels, "Información por IP Source", entropia)


    def graficarEntropias(self, entropia_src,entropia_dst,cant_pkt_arp):
        """ Grafico entropias vs cant_pkt_arp """
        labels = ["IP Src", "IP Dst"]
        self.graficar(cant_pkt_arp, [entropia_src, entropia_dst], "Cantidad", "Entropia", labels, "Entropia a medida que crece cantidad")
