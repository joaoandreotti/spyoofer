import struct

class InternetProtocol6:
    def __init__(self, datagram):
        self.VersionTrafficClassFlowLabel, self.PayloadLength,\
                self.NextHeader, self.HopLimit, self.SourceAddress,\
                self.DestinationAddress =\
                struct.unpack('! 4s 2s s s 16s 16s', datagram[:40])
        self.Data = datagram[40:]
