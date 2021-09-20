import struct

class AddressResolutionProtocol():
    def __init__(self, ethernetObject):
        self.Ethernet = ethernetObject
        self.ARPTypeID = b'\x08\x06'

    def CreateARPRequestPacket(self, protocolType, protocolAddressLength, sourceIP, destinationIP):
        arpPacket = b''
        arpPacket += b'\x00\x01'
        arpPacket += protocolType
        arpPacket += b'\x06'
        arpPacket += protocolAddressLength
        arpPacket += b'\x00\x01'
        arpPacket += self.Ethernet.GetInterfaceMAC()
        arpPacket += sourceIP
        arpPacket += b'\x00\x00\x00\x00\x00\x00'
        arpPacket += destinationIP
        return arpPacket

    def CreateARPReplyPacket(self, protocolType, protocolAddressLength, sourceIP, destinationMAC, destinationIP):
        arpPacket = b''
        arpPacket += b'\x00\x01'
        arpPacket += protocolType
        arpPacket += b'\x06'
        arpPacket += protocolAddressLength
        arpPacket += b'\x00\x02'
        arpPacket += self.Ethernet.GetInterfaceMAC()
        arpPacket += sourceIP
        arpPacket += destinationMAC
        arpPacket += destinationIP
        return arpPacket

    def SendARPRequest(self, protocolType, sourceIP, destinationMAC, destinationIP):
        protocolAddressLength = self.GetProtocolAddressLength(protocolType)
        arpPacket = self.CreateARPRequestPacket(protocolType, protocolAddressLength, sourceIP, destinationIP)
        sourceMAC = self.Ethernet.GetInterfaceMAC()
        self.Ethernet.SendFrame(destinationMAC, sourceMAC, self.ARPTypeID, arpPacket)

    def SendARPReply(self, protocolType, sourceIP, destinationMAC, destinationIP):
        protocolAddressLength = self.GetProtocolAddressLength(protocolType)
        arpPacket = self.CreateARPReplyPacket(protocolType, protocolAddressLength, sourceIP, destinationMAC, destinationIP)
        sourceMAC = self.Ethernet.GetInterfaceMAC()
        self.Ethernet.SendFrame(destinationMAC, sourceMAC, self.ARPTypeID, arpPacket)

    def ReceiveARPReply(self):
        (destinationMAC, sourceMAC, receivedTypeID, data) = self.Ethernet.ReceiveFrame(self.ARPTypeID, timeout = 1)
        return self.ParseARPReply(data)

    def ReceiveARPRequest(self):
        (destinationMAC, sourceMAC, receivedTypeID, data) = self.Ethernet.ReceiveFrame(self.ARPTypeID, timeout = 1)
        return self.ParseARPRequest(data)

    def ParseARPRequest(self, data):
        if data[6:8] in b'\x00\x01':
            return struct.unpack('! 2s 2s 1s 1s 2s 6s 4s 6s 4s', data[:28])

    def ParseARPReply(self, data):
        if data[6:8] in b'\x00\x02':
            return struct.unpack('! 2s 2s 1s 1s 2s 6s 4s 6s 4s', data[:28])

    def GetProtocolAddressLength(self, protocolType):
        if protocolType in b'\x08\x00':
            return b'\x04'

    def GetTargetMAC(self, protocolType, sourceIP, targetIP):
        while True:
            try:
                self.SendARPRequest(protocolType, sourceIP, b'\xff\xff\xff\xff\xff\xff', targetIP)
                arpInfo = self.ReceiveARPReply()
                return arpInfo[5]
            except TypeError:
                break
            except:
                continue

    def SpoofTargetMAC(self, protocolType, sourceIP, targetMAC, targetIP):
        self.SendARPReply(protocolType, targetIP, targetMAC, sourceIP)

