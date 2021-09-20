import netifaces
import struct
from iface_socket import *

class EthernetII(Socket):
    def __init__(self, sourceInterface):
        super(EthernetII, self).__init__(sourceInterface)
        self.Interface = sourceInterface

    def CreateFrame(self, destinationMAC, sourceMAC, typeID, data):
        frame = b''
        frame += destinationMAC
        frame += sourceMAC
        frame += typeID
        frame += data
        return frame

    def ParseFrame(self, data):
        destinationMAC, sourceMAC, typeID = \
                struct.unpack('! 6s 6s 2s', data[:14])
        return (destinationMAC, sourceMAC, typeID, data[14:])

    def SendFrame(self, destinationMAC, sourceMAC, typeID, data):
        frame = self.CreateFrame(destinationMAC, sourceMAC, typeID, data)
        self.Socket.send(frame)

    def ReceiveFrame(self, typeID = b'', timeout = None):
        destinationMAC = None
        sourceMAC = None
        receivedTypeID = None
        data = None
        self.Socket.settimeout(timeout)
        while receivedTypeID is None or typeID not in receivedTypeID:
            (frame, senderInfo) = self.Socket.recvfrom(4096)
            (destinationMAC, sourceMAC, receivedTypeID, data) = self.ParseFrame(frame)
        return (destinationMAC, sourceMAC, receivedTypeID, data)

    def GetInterfaceMAC(self):
        interfaceMAC = netifaces.ifaddresses(self.Interface)[netifaces.AF_LINK][0]['addr'].encode()
        return bytes([int(byte, 16) for byte in interfaceMAC.split(b':')])
