from scapy.all import *

#before use ifconfig prism0 up



ap_list = []
interface = "prism0"


def handler(pkts):
    if pkts.haslayer(Dot11):
        if pkts.type == 0 and pkts.subtype == 8:
            if pkts.addr2 not in ap_list:
                ap_list.append(pkts.addr2)
                print("SSID --> {} -- BSSID -> {} -- channel --> {} ".format(pkts.info,pkts.addr2, ord(pkts[Dot11Elt:3].info)))
            
sniff(iface="prism0", prn=handler)


