#!/usr/bin/python3

import socket
sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
sniff.bind(("prism0", 0x0003))
ap_list =[]
while True:
    fm1 = sniff.recvfrom(6000)

    fm = fm1[0]
    if fm[26] == '\x80':
        if fm[36:42] not in ap_list:
            ap_list.append(fm[36:42])
            a = ord(fm[63])
            print("SSID --> {}, BSSID --> {}, channel --> {}".format(\
                fm[64:64+a]), fm[36:42].encode('hex'),ord(fm[64 + a + 12]))


            
          
