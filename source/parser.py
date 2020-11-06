#!/usr/bin/env python3
from source.lib import *
from source.packets import Packets
import re
import pdb

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

        #for category, _ in self.packets.extractors.items():
        #    for k,v in self.packets.dicts[category].items():
        #        print(category, k, len(v))
        #print('total', len(self.packets.packets))
        # TODO remove pcap_content to save memory?
        # TODO or do bulk processing?



class TCPReassembler: # TODO get general stuff into generalized class
    """
    class holds ordered reassembled chunks and allows to travel back and forth
    """
    def __init__(self, stream, packets):
        self.chunks = [] # (is_server, chunk)
        packet_chunks = [] # (is_server, [packets])
        self.pointer = 0

        tmp_packets = []
        tmp_is_server = None
        
        for p in packets:
            is_server = layer3(p).src == stream[3] and layer4(p).sport == stream[4]
            
            if is_server != tmp_is_server:
                # change of communication direction
                if tmp_packets:
                    # any data from the previous chunk? store and flush tmp
                    packet_chunks.append((tmp_is_server, tmp_packets))
                    tmp_packets = []
                elif packet_chunks:
                    # useless interruption, continue with previous chunk
                    tmp_packets = packet_chunks.pop()[1]
                tmp_is_server = is_server
            # push packets into tmp
            if (isinstance(layer4(p).payload, Raw) 
                and not isinstance(layer4(p).payload, Padding)): # TODO other types?
                tmp_packets.append(p)

        # now sort those chunks, ditch duplicate seqs and get payloads
        # TODO do with seq anyway?
        for is_server, packets in packet_chunks:
            fixed_packets = []
            seqs = []
            
            for i, p in enumerate(packets):
                new_seq = layer4(p).seq
                if new_seq in seqs:
                    fixed_packets = [x for x in fixed_packets if x.seq != new_seq]
                else:
                    seqs.append(layer4(p).seq)
                fixed_packets.append(p)
            fixed_packets.sort(key=lambda p: layer4(p).seq)
            for p in fixed_packets:
                """#
                if isinstance(layer4(p).payload, Raw):
                    if len(layer4(p).payload) > 30:
                        print('S' if is_server else 'C', bytes(layer4(p).payload)[:15].replace(b'\r\n', b'\\r\\n'), '...', bytes(layer4(p).payload)[-15:].replace(b'\r\n', b'\\r\\n'))
                    else:
                        print('S' if is_server else 'C', bytes(layer4(p).payload).replace(b'\r\n', b'\\r\\n'))
                """#
            data = b''.join(bytes(layer4(p).payload) for p in fixed_packets)
            self.chunks.append((is_server, data))
        
    
    def seek_start(self):
        self.pointer = 0
        return self

    def seek_end(self):
        self.pointer = len(self.chunks) - 1
        return self

    def matches(self, is_server=None, regex=None):
        # client/server condition is not satisfied?
        if is_server is not None and is_server != self.chunks[self.pointer][0]:
            return False
        # regex does not match?
        if regex and not re.search(regex, self.chunks[self.pointer][1], re.I):
            return False
        return True
        
        
    def _step_(self, step, is_server=None, regex=None, current=False, lookonly=False):
        """
        find next/previous matching chunk (by client/server or pattern)
        also test current chunk if desired
        move pointer if desired
        """
        old_pointer = self.pointer
        if current:
            self.pointer -= step
        
        while True:
            self.pointer += step
            if not self.matches(is_server, regex):
                continue
            break

        if lookonly:
            self.pointer = old_pointer
        return self
            
        
    def next(self, is_server=None, regex=None, current=False, lookonly=False):
        return self._step_(1, is_server, regex, current, lookonly) 

    def previous(self, is_server=None, regex=None, current=False, lookonly=False):
        return self._step_(-1, is_server, regex, current, lookonly) 

    def get(self):
        return self.chunks[self.pointer]

    def __str__(self):
        result = ''
        for i, (is_server, data) in enumerate(self.chunks):
            result += f'{i}: {"server" if is_server else "client"}\n'
            result += str(data).replace('\\r\\n', '\r\n').replace('\\t', '\t')
            result += '\n\n'
        return result

    

