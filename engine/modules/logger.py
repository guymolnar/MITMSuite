from engine.modules.base import Module

class LoggerModule(Module):
    def process(self, packet):
        print(packet.summary())
        return packet