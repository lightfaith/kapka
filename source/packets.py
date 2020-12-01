#!/usr/bin/env python3
import traceback
from source.lib import *
from collections import OrderedDict

class Packets:
    """
    Packets links given scapy structures by many keys
    - source address
    - destination address
    - source port
    - destination port
    - any port (two-way communication)
    - server ip & port?
    - application layer protocol
    - individual packet by packet number
    - chunks by packet number?
    - chunks by time? 
    - stream
    - conversation (IP pair)
    """
    def __init__(self):
        self.packets = [] # original list of packets, parsed by scapy
        # TODO how about reassembling?
        self.dicts = {} # key: list of matching packets
        self.extractors = {} # key: function to extract it from a packet
        #self.preselect_extractors = {} # key: (function to extract candidate from packet,
                                       #       function to extract matching candidates)
        """
        key: OrderedDict() for key in [
            #'saddr',
            #'daddr',   
            #'sport',   
            #'dport',
            #'anyport',
            #'server_socket',
            'appproto',
            'number',
            'chunk',
            'time',
            'stream',
        ]}
        """

    def add_extractor(self, key, function, data=None):
        self.extractors[key] = (function, data)
   
    def concat_dicts(self, new, olds):
        self.dicts[new] = {}
        for old in olds:
            for k,v in self.dicts[old].items():
                if k not in self.dicts[new]:
                    self.dicts[new][k] = []
                self.dicts[new][k].extend(v)


    def add(self, packets):
        debug('Adding packets for data extraction.', indent=2)
        self.packets = packets
        # TODO get time and choose time chunk size
        for packet in self.packets:
            # run normal extractors
            for category, (extract, support_data) in self.extractors.items():
                if not self.dicts.get(category):
                    self.dicts[category] = {}
                try:
                    key = extract(packet, support_data or [])
                except AttributeError:
                    traceback.print_exc() # 
                    continue
                except:
                    traceback.print_exc()
                    continue
                if key:
                    if not self.dicts[category].get(key):
                        self.dicts[category][key] = []
                    self.dicts[category][key].append(packet)
            """
            # run preselect part 2
            for category, (f1, f2) in self.preselect_extractors.items():
                extracted = f1(packet)
                if extracted and f2(packet, self.dicts[category].keys()):
                    self.dicts[category][extracted].append(packet)
            """

        
    def test(self): # TODO delete
        self.packets = [(x, x*2) for x in range(5000)]
        self.dicts = {'mod2': {
                        'liche': [x for x in self.packets if x[0] % 2 == 1],
                        'sude': [x for x in self.packets if x[0] % 2 == 0]
                        }
                    }

    def by(self, key, value=None):
        """
        returns lists of packets by desired key
        usage: smtp = packets.by('anyport', 25)
        """
        if value:
            debug(f'Getting packet sets by {key}: {value}...')
        else:
            debug(f'Getting packet sets by {key}...')

        if value is None:
            try:
                return self.dicts[key]
            except KeyError:
                return []
        if key == 'number':
            try:
                return self.packets[value]
            except KeyError:
                return None
        try:
            return self.dicts[key][value]
        except KeyError:
            traceback.print_exc()
            return []
        return []

