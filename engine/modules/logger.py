from datetime import datetime
from engine.modules.base import Module

class LoggerModule(Module):
    def __init__(self):
        self._file = None

    def start(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._file = open(f"capture_{timestamp}.log", "w")

    def stop(self):
        if self._file:
            self._file.close()
            self._file = None

    def process(self, packet):
        if self._file:
            self._file.write(packet.summary() + "\n")
            self._file.flush()
        return packet
