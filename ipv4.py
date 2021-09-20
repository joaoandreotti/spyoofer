import struct

class InternetProtocol4:
    def __init__(self, datagram):
        self.VersionIHL, self.TOS, self.TotalLenght, self.Identification,\
                self.FlagsFragmentOffset, self.TTL, self.Protocol,\
                self.HeaderChecksum, self.SourceAddress, self.DestinationAddress =\
                struct.unpack('! s s 2s 2s 2s s s 2s 4s 4s', datagram[:20])
        self.Data = datagram[20:]

    def GetIPv4Packet(self):
        self.VersionIHL + self.TOS + self.TotalLenght + self.Identification +\
                self.FlagsFragmentOffset + self.TTL + self.Protocol +\
                self.HeaderChecksum + self.SourceAddress + self.DestinationAddress + self.Data
