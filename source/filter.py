class Filter:

    def __init__(self, src, dst, sport, dport, protocol, connector):
        self.result = ''
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.protocol = protocol
        self.connector = connector

    def translate(self):
        filter_parts = []
        if self.src:
            filter_parts.append('src host ' + self.src)
        if self.dst:
            filter_parts.append('dst host ' + self.dst)
        if self.sport:
            filter_parts.append('src port ' + self.sport)
        if self.dport:
            filter_parts.append('dst port ' + self.dport)
        if self.protocol:
            filter_parts.append(self.protocol)
        return self.connector.join(filter_parts)
