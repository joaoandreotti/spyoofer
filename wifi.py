import struct
from iface_socket import *
from frame_types import *


class Wifi80211(Socket):
    def __init__(self, sourceInterface):
        super(Wifi80211, self).__init__(sourceInterface)

    def ParseFrame(self, frame):
        (types, flags) = struct.unpack('! B B', frame[:2])
        print(frameType[types])

    def ReceiveFrame(self):
        while True:
            (frame, senderInfo) = self.Socket.recvfrom(4096)
            length = struct.unpack('< H', frame[2:4])[0]
            frame = self.ParseFrame(frame[length:])

wifi = Wifi80211('wlan0mon')
wifi.ReceiveFrame()
