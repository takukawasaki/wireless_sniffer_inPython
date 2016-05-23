from scapy.all import *

interface = 'prism0'

i=1

def info(fm):
    if fm.haslayer(Dot11):
        if ((fm.type == 0) & (fm.subtype==12)):
            global i
            print("Deauth detected {}".format(i))
            i = i + 1
sniff(iface=interface,prn=info)
