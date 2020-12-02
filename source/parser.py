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
    def unify_directional_streams(streams):
        """
        lower port is probably the server
        """
        result = set()
        for s in streams:
            directions = [s, (s[0], s[3], s[4], s[1], s[2])]
            result.add(sorted(directions, key=lambda x: x[4])[0])
        return result

    def __init__(self, pcap_file):
        debug(f'Parsing {pcap_file}')
        self.pcap_content = rdpcap(pcap_file)
        self.packets = Packets()
        
        # fill the multidict
        self.packets.add_extractor('saddr', lambda packet, _: layer3(packet).src)
        self.packets.add_extractor('daddr', lambda packet, _: layer3(packet).dst)
        self.packets.add_extractor('sport', lambda packet, _: layer4(packet).sport)
        self.packets.add_extractor('dport', lambda packet, _: layer4(packet).dport)
        """
        tcp_servers = set([(layer3(p).src, layer4(p).sport) 
                       for p in self.pcap_content 
                       if p.haslayer(TCP) and p[TCP].flags == 0x12])
        streams = set([get_socket(p)
                       for p in self.pcap_content
                       if p.haslayer(UDP) or (p.haslayer(TCP) and p[TCP].flags == 0x2)])
        """
        streams = Parser.unify_directional_streams(
            set([get_socket(p)
                for p in self.pcap_content
                if p.haslayer(UDP) or p.haslayer(TCP)]))
        
        tcp_servers = [(s[3], s[4]) for s in streams if s[0] == 6]

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

        debug(f'processed {len(self.pcap_content)} packets.', indent=2)
        debug(f'processed {len(tcp_servers)} TCP servers.', indent=2)
        debug(f'processed {len(streams)} streams.', indent=2)
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

        # gather lists of packets with regards to communication direction changes
        # filter out interruptions (ACKs etc.)
        debug('Reassembling stream...', indent=2)
        for p in packets:
            # is communication direction changed?
            is_server = layer3(p).src == stream[3] and layer4(p).sport == stream[4]
            if is_server != tmp_is_server:
                if tmp_packets:
                    # any data from the previous chunk? store and flush tmp
                    packet_chunks.append((tmp_is_server, tmp_packets))
                    tmp_packets = []
                elif packet_chunks:
                    # useless interruption, continue with previous chunk
                    tmp_packets = packet_chunks.pop()[1]
                tmp_is_server = is_server

            # add chunk into seq_chunk
            if (isinstance(layer4(p).payload, Raw) 
                and not isinstance(layer4(p).payload, Padding)): # TODO other types?
                tmp_packets.append(p)
                

        # for each list of packets (chunks-to-be) do SEQ reassembling
        for is_server, packets in packet_chunks:
            seq_offset = min(p[TCP].seq for p in packets)
            real_chunk_size = max(p[TCP].seq + len(p[TCP].payload) for p in packets) - seq_offset
            byte_chunk = bytearray(b'\x00' * real_chunk_size)
            for packet in packets:
                start = packet[TCP].seq - seq_offset
                end = start + len(packet[TCP].payload)
                byte_chunk[start:end] = bytes(packet[TCP].payload)
            # TODO can we do integrity check for the chunk somehow?
            self.chunks.append((is_server, byte_chunk))

    
    def seek_start(self):
        self.pointer = 0
        return self

    def seek_end(self):
        self.pointer = len(self.chunks) - 1
        return self

    def matches(self, is_server=None, regex=None):
        # client/server condition is not satisfied?
        #print(self.chunks[self.pointer][1][:50])
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

    def get(self, pointer=None):
        if pointer is None:
            pointer = self.pointer
        return self.chunks[pointer]

    def find_all(self, is_server=None, regex=None):
        matches = []
        current_pointer = self.pointer
        self.seek_start()
        
        use_current = True
        try:
            self.next(is_server=is_server, regex=regex, current=True)
            matches.append(self.pointer)
            while True:
                self.next(is_server=is_server, regex=regex)
                matches.append(self.pointer)
        except IndexError:
            pass

        self.pointer = current_pointer
        return matches


    def __str__(self):
        result = ''
        for i, (is_server, data) in enumerate(self.chunks):
            result += f'{i}: {"server" if is_server else "client"}\n'
            result += str(data).replace('\\r\\n', '\r\n').replace('\\t', '\t')
            result += '\n\n'
        return result

    def __lt__(self, other):
        if isinstance(other, int):
            return self.pointer < other
        else:
            return self.pointer < other.pointer
            
    def __le__(self, other):
        if isinstance(other, int):
            return self.pointer <= other
        else:
            return self.pointer <= other.pointer

    def __gt__(self, other):
        if isinstance(other, int):
            return self.pointer > other
        else:
            return self.pointer > other.pointer

    def __ge__(self, other):
        if isinstance(other, int):
            return self.pointer >= other
        else:
            return self.pointer >= other.pointer


