#!/usr/bin/env python3
from source.lib import *
from source.packets import Packets

class Parser:
    """
    Parser takes care of parsing pcap into Scapy structures. 
    Packets() object allows queries by many distinct keys
    """
    def __init__(self, pcap_file):
        self.pcap_content = rdpcap(pcap_file)
        self.packets = Packets()
        
        # fill the multidict
        self.packets.add_extractor('saddr', lambda packet, _: layer3(packet).src)
        self.packets.add_extractor('daddr', lambda packet, _: layer3(packet).dst)
        self.packets.add_extractor('sport', lambda packet, _: layer4(packet).sport)
        self.packets.add_extractor('dport', lambda packet, _: layer4(packet).dport)
        tcp_servers = set([(layer3(p).src, layer4(p).sport) 
                       for p in self.pcap_content 
                       if p.haslayer(TCP) and p[TCP].flags == 0x12])
        streams = set([get_socket(p)
                       for p in self.pcap_content
                       if p.haslayer(UDP) or (p.haslayer(TCP) and p[TCP].flags == 0x2)])
        
        self.packets.add_extractor('serversocket',
                                   lambda packet, data: ((layer3(packet).src, layer4(packet).sport) 
                                                         if (layer3(packet).src, layer4(packet).sport) in data
                                                         else (layer3(packet).dst, layer4(packet).dport)
                                                         if (layer3(packet).dst, layer4(packet).dport) in data
                                                         else None),
                                   tcp_servers)
        self.packets.add_extractor('stream',
                                   lambda packet, data: (get_socket(packet) 
                                                         if get_socket(packet) in data
                                                         else get_socket_rev(packet)
                                                         if get_socket_rev(packet) in data
                                                         else None),
                                   streams)
        

        self.packets.add(self.pcap_content)
        self.packets.concat_dicts('anyport', ('sport', 'dport'))

        for category, _ in self.packets.extractors.items():
            for k,v in self.packets.dicts[category].items():
                print(category, k, len(v))
        print('total', len(self.packets.packets))
        # TODO remove pcap_content to save memory?
        # TODO or do bulk processing?


    

