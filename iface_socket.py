import socket

class Socket():
    def __init__(self, sourceInterface):
        try:
            self.Interface = sourceInterface
            self.Socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.Socket.bind((self.Interface, 0))
        except Exception as e:
            raise Exception(e)

    def __del__(self):
        try:
            self.Socket.close()
        except Exception as e:
            raise Exception(e)
