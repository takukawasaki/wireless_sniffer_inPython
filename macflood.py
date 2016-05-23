from  scapy.all import *


num = raw_input("Enter the number of packets: ")

interface = raw_input("Enter the interface: ")

eth_packet = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
arp_packet = ARP(pdst='192.168.1.255', hwdst="ff:ff:ff:ff:ff:ff")



try:
    sendp(eth_packet/arp_packet, iface="prism0", count=num, inter=.1)
except:
    print("Destination unreachable ")
