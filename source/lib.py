#!/usr/bin/env python3
import subprocess
import os
from scapy.all import *

class Output:
    folder = ''

def run_command(command):
    p = subprocess.Popen(command,
                         shell=True,
                         #stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         )
    (out, err) = p.communicate()
    return (p.returncode, out, err)

def create_folder(path, subfolder=True):
    try:
        os.mkdir(os.path.join(Output.folder, path) if subfolder else path)
    except FileExistsError:
        pass

def save_result(path, command_result, formatter=lambda x: x):
    returncode, out, err = command_result
    #print(output_folder, returncode, out, err)
    with open(os.path.join(Output.folder, path), 'wb') as f:
        f.write(formatter(out))

def save_data(path, data, formatter=lambda x: x):
    if isinstance(data, str):
        data = data.encode()
    with open(os.path.join(Output.folder, path), 'wb') as f:
        print(f.name)
        f.write(formatter(data))

def format_kbps(data_len, duration):
    return data_len * 8 // duration / 1000

def symlinks(source, protocol, stream, protocol_altname=None):
    subfolders = []
    proto = layer4_dict.get(stream[0])
    if proto:
        subfolders.append(f'dport/{proto}_{stream[4]}')
    subfolders.append(f'protocol/{protocol}')
    subfolders.append(f'source/{stream[1]}')
    subfolders.append(f'destination/{stream[3]}')
    for subfolder in subfolders:
        create_folder(subfolder)
        # allow alternative name for symlinks (e.g. mail id for SMTP)
        dest_name = (protocol_altname 
                     if (protocol_altname and subfolder.startswith('protocol/')) 
                     else os.path.basename(source))
        dest = os.path.join(Output.folder, subfolder, dest_name)
        relative_source = os.path.relpath(os.path.join(Output.folder, source), 
                                 start=os.path.join(Output.folder, subfolder))
        try:
            os.symlink(relative_source, dest)
        except FileExistsError:
            pass

layer3 = lambda packet: (packet[IP]
		       if packet.haslayer(IP)
		       else packet[IPv6]
		       if packet.haslayer(IPv6)
		       else None)
layer4 = lambda packet: (packet[TCP]
		       if packet.haslayer(TCP)
		       else packet[UDP]
		       if packet.haslayer(UDP)
		       else None)
get_socket = lambda packet: (layer3(packet).proto,
			   layer3(packet).src, layer4(packet).sport,
			   layer3(packet).dst, layer4(packet).dport)
get_socket_rev = lambda packet: (layer3(packet).proto,
			       layer3(packet).dst, layer4(packet).dport,
			       layer3(packet).src, layer4(packet).sport)

format_ip = lambda ip: f'[{ip}]' if ':' in ip else f'{ip}'

follow_all = lambda packets: b''.join(bytes(layer4(p).payload) for p in packets)
follow_client = lambda stream, packets: b''.join(bytes(layer4(p).payload) 
                                                 for p in packets
                                                 if layer3(p).src == stream[1]
                                                 and layer4(p).sport == stream[2])
follow_server = lambda stream, packets: b''.join(bytes(layer4(p).payload) 
                                                 for p in packets
                                                 if layer3(p).src == stream[3]
                                                 and layer4(p).sport == stream[4])



layer4_dict = {
    6: 'tcp',
    17: 'udp', 
}

layer7_dict = {
    'ftp_data': ('tcp', [20]),
    'ftp': ('tcp', [21]),
    'ssh': ('tcp', [22]),
    'telnet': ('tcp', [23]),
    'smtp': ('tcp', [25]),
    'dns_tcp': ('tcp', [53]),
    'http': ('tcp', [80]),
    'pop3': ('tcp', [110]),
    'imap': ('tcp', [143]),
    'https': ('tcp', [443]),
    'smb': ('tcp', [445]),
    'smtps': ('tcp', [465]),
    'imaps': ('tcp', [993]),
    'pop3s': ('tcp', [995]),

    'dns': ('udp', [53]),
    'dhcp_server': ('udp', [67]),
    'dhcp_client': ('udp', [68]),
    'tftp': ('udp', [69]),
}
