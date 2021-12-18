import re


class Searcher:

    def __init__(self, packet_list, searches: str):
        self.packet_list = packet_list
        self.search_list = searches.lower().split(';')
        self.result = []

    def search(self):
        self.result.clear()
        for search in self.search_list:
            search = search.replace(' ', '')
            if match := re.match(r'(.+)\.(.+)=(.+)', search):
                layer = match.group(1)
                key = match.group(2)
                value = match.group(3)
                for packet in self.packet_list:
                    for p_layer, p_layer_info in packet.detail_info.items():
                        if layer == p_layer.lower():
                            for p_key, p_value in p_layer_info.items():
                                if key in p_key and p_value == value:
                                    self.result.append(packet)
            elif match := re.match(r'(.+)in(.+)\.(.+)', search):
                value = match.group(1)
                layer = match.group(2)
                key = match.group(3)
                for packet in self.packet_list:
                    for p_layer, p_layer_info in packet.detail_info.items():
                        if layer == p_layer.lower():
                            for p_key, p_value in p_layer_info.items():
                                if key in p_key and value in p_value:
                                    self.result.append(packet)
            elif match := re.match(r'(.+)', search):
                protocol = match.group(1)
                for packet in self.packet_list:
                    if packet.protocol.lower() == protocol:
                        self.result.append(packet)
            else:
                pass

        return self.result
