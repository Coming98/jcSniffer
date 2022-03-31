from scapy.all import raw

def handleTCP(packet, infos, brief):
    tcp_layer = packet['TCP']
    if(brief):
        if(tcp_layer.dport == 80 or tcp_layer.sport == 80):
            infos['Protocol'] = 'HTTP'
            if packet.haslayer('HTTPRequest'):
                http_method = packet.sprintf("{HTTPRequest:%HTTPRequest.Method%}").strip("'")
                http_path = packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}").strip("'")
                http_version = packet.sprintf("{HTTPRequest:%HTTPRequest.Http-Version%}").strip("'")
                Info = f'{http_method} {http_path} {http_version}'
            elif packet.haslayer('HTTPResponse'):
                Info = packet.sprintf("{HTTPResponse:%HTTPResponse.Status-Line%}").strip("'")
            else:
                Info = ''
            infos['Info'] = Info
        else:
            infos['Protocol'] = 'TCP'
            flags = [tcp_layer.flags.A, tcp_layer.flags.R, tcp_layer.flags.S, tcp_layer.flags.F, tcp_layer.flags.U, tcp_layer.flags.P]
            msgs = ['ACK', 'RST', 'SYN', 'FIN', 'URG', 'PSH']
            msg = ', '.join([f'{msgs[i]}' for i, flag in enumerate(flags) if flag])
            infos['Info'] = f'{tcp_layer.sport} -> {tcp_layer.dport} [{msg}] Seq: {tcp_layer.seq}, ACK: {tcp_layer.ack}, WIN: {tcp_layer.window}'
    else:
        infos_list = infos
        tcp_infos = {
            'brief_name': 'TCP',
            'header': f'TCP',
            'childs': [
                {'header': f'Sport: {tcp_layer.sport}'},
                {'header': f'Dport: {tcp_layer.dport}'},
                {'header': f'Seq: {tcp_layer.seq}'},
                {'header': f'Ack: {tcp_layer.ack}'},
                {'header': f'数据偏移: {tcp_layer.dataofs}'},
                {'header': f'保留位: {tcp_layer.reserved}'},
                {'header': f'flags: {tcp_layer.flags}'},
                {
                    'header': f'flags: {tcp_layer.flags}',
                    'childs': [
                        {'header': f'ACK: {tcp_layer.flags.A}'},
                        {'header': f'RST: {tcp_layer.flags.R}'},
                        {'header': f'SYN: {tcp_layer.flags.S}'},
                        {'header': f'FIN: {tcp_layer.flags.F}'},
                        {'header': f'URG: {tcp_layer.flags.U}'},
                        {'header': f'PSH: {tcp_layer.flags.P}'},
                    ]
                },
                {'header': f'window: {tcp_layer.window}'},
                {'header': f'chksum: {tcp_layer.chksum}'},
                {'header': f'紧急指针: {tcp_layer.urgptr}'},
                {'header': f'options: {tcp_layer.options}'},
            ]
        }
        infos_list.append(tcp_infos)

        if(tcp_layer.dport == 80 or tcp_layer.sport == 80):
            pass


def handleUDP(packet, infos, brief):
    udp_layer = packet['UDP']
    if(brief):
        infos['Protocol'] = 'UDP'
        infos['Info'] = f'{udp_layer.sport} -> {udp_layer.dport} length: {udp_layer.len}'
    else:
        infos_list = infos
        udp_infos = {
            'brief_name': 'UDP',
            'header': f'User Datagram Protocol, Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}',
            'childs': [
                {'header': f'Source Port: {udp_layer.sport}'},
                {'header': f'Destination Port: {udp_layer.dport}'},
                {'header': f'Length: {udp_layer.len}'},
                {'header': f'Checksum: {hex(udp_layer.chksum)} ({udp_layer.chksum})'},
            ]
        }
        if(packet.haslayer('Raw')):
            udp_infos['childs'].append(
                {'header': f'UDP Payload: {packet["Raw"].load}'}
            )
        infos_list.append(udp_infos)
def handleICMP(packet, infos, brief):
    icmp_layer = packet['ICMP']
    if(brief):
        infos['Protocol'] = 'ICMP'
        type_info_dict = {
            0: 'reply',
            8: 'request'
        }
        type_info = icmp_layer.type if icmp_layer.type not in type_info_dict else type_info_dict[icmp_layer.type]
        infos['Info'] = f'Echo (ping) {type_info} id: {icmp_layer.id} seq: {icmp_layer.seq}'
    else:
        infos_list = infos
        icmp_type = icmp_layer.type
        icmp_type_info = '(Echo (ping) request)' if icmp_type == 8 else ('(Echo (ping) reply)' if icmp_type == 0 else '')
        icmp_infos = {
            'brief_name': 'ICMP',
            'header': 'ICMP',
            'childs': [
                {'header': f'Type: {icmp_type}, {icmp_type_info}'},
                {'header': f'Code: {icmp_layer.code}'},
                {'header': f'Chksum: {icmp_layer.chksum}'},
                {'header': f'id: {icmp_layer.id}'},
                {'header': f'seq: {icmp_layer.seq}'},
                {'header': f'ts_ori: {icmp_layer.ts_ori}'},
                {'header': f'ts_rx: {icmp_layer.ts_rx}'},
                {'header': f'ts_tx: {icmp_layer.ts_tx}'},
                {'header': f'gw: {icmp_layer.gw}'},
                {'header': f'ptr: {icmp_layer.ptr}'},
                {'header': f'Reserved: {icmp_layer.reserved}'},
                {'header': f'Length: {icmp_layer.length}'},
                {'header': f'addr_mask: {icmp_layer.addr_mask}'},
                {'header': f'nexthopmtu: {icmp_layer.nexthopmtu}'},
            ]
        }
        infos_list.append(icmp_infos)
def handleIGMP(packet, infos, brief):
    if(brief):
        infos['Protocol'] = 'IGMP'
        infos['Info'] = 'IGMP infos...'
    else:
        infos_list = infos
        igmp_infos = {
            'brief_name': 'IGMP',
            'header': 'IGMP'
        }

def handleNone(packet, infos, brief):
    protocol = packet['IP'].proto
    infos['Protocol'] = f'{protocol}'
    infos['Info'] = 'unknow infos...'

def handleIProtocol(packet, protocol, infos, brief):
    if(protocol == 6): # TCP
        handleTCP(packet, infos, brief)
    elif(protocol == 17): # UDP
        handleUDP(packet, infos, brief)
    elif(protocol == 1): # ICMP
        handleICMP(packet, infos, brief)
    elif(protocol == 2): # IGMP
        handleIGMP(packet, infos, brief)
    else:
        handleNone(packet, infos, brief)

def handleIP(packet, brief):
    infos = {
        'Source': packet['IP'].src,
        'Destinaiton': packet['IP'].dst,
        'Length': len(packet),
    }

    protocol = packet['IP'].proto
    proto_dict = {
        17: 'UDP',
        6: 'TCP',
        1: 'ICMP',
        2: 'IGMP'
    }
    if(brief):
        handleIProtocol(packet, protocol, infos, brief=brief)
        return infos
    else:
        ip_layer = packet['IP']
        infos_list = [
                {
                'brief_name': 'IPV4',
                'header': f'Internet Protocol Version 4, Src: {ip_layer.src}, Dst: {ip_layer.dst}',
                'childs' : [
                    { 'header': f'Version: {ip_layer.version}' },
                    { 'header': f'Header Length: ({ip_layer.ihl}) {"20 bytes" if ip_layer.ihl == 5 else ""}' },
                    { 'header': f'Total Length: {ip_layer.len}' },
                    { 'header': f'Identification: {hex(ip_layer.id)} ({ip_layer.id})' },
                    { 
                        'header': f'Flags: {hex(ip_layer.flags.value)}',
                        'childs': [
                            {'header': f'Don\'t fragment (DF): {"Not set" if not ip_layer.flags.DF else "Set"}' },
                            {'header': f'More fragments (MF): {"Not set" if not ip_layer.flags.MF else "Set"}' },
                        ]
                    },
                    {'header': f'Fragment Offset: {ip_layer.frag}' },
                    {'header': f'Time to Live(ttl): {ip_layer.ttl}' },
                    {'header': f'Protocol: {proto_dict.get(protocol)} ({protocol})' },
                    { 'header': f'Source Address: {ip_layer.src}' },
                    { 'header': f'Destination Address: {ip_layer.dst}' },
                ]
            },
        ]
        handleIProtocol(packet, protocol, infos_list, brief=brief)
        return infos_list

def handleARP(packet, brief):

    arp_layer = packet['ARP']
    if(brief):
        infos = {
            'Source': arp_layer.psrc,
            'Destinaiton': arp_layer.pdst,
            'Length': len(packet),
            'Protocol': 'ARP'
        }

        if(arp_layer.op == 1):
            # ASK
            Info = f'Who know {arp_layer.pdst}? Tell {arp_layer.psrc} please.'
        elif(arp_layer.op == 2):
            # Reply
            Info = f'{arp_layer.psrc} is at {arp_layer.hwsrc}'
        else:
            Info = f'ARP infos... {arp_layer.op}'

        infos['Info'] = Info

        return infos
    else:
        proto_dict = {
            0x800: 'IPv4',
            0x86dd: 'Ipv6'
        }
        action_name = 'request' if arp_layer.op == 1 else ('answer' if arp_layer.op == 2 else 'unknow action')
        infos_list = [
            {
                'brief_name': 'ARP',
                'header': f'Address Resolution Protocol ({action_name})',
                'childs' : [
                    { 'header': f'Hardware type: Ethernet ({arp_layer.hwtype})' },
                    { 'header': f'Protocol type: {proto_dict.get(hex(arp_layer.ptype), "Unknow")} ({hex(arp_layer.ptype)})' },
                    { 'header': f'Hardware size: {arp_layer.hwlen}' },
                    { 'header': f'Protocol size: {arp_layer.plen}' },
                    { 'header': f'Opcode: {action_name} ({arp_layer.op})' },
                    { 'header': f'Sender MAC address: {arp_layer.hwsrc}' },
                    { 'header': f'Sender IP address: {arp_layer.psrc}' },
                    { 'header': f'Target MAC address: {arp_layer.hwdst}' },
                    { 'header': f'Target IP address: {arp_layer.pdst}' },
                ]
            }
        ]
        return infos_list

def handleIpv6(packet, brief):
    ipv6_layer = packet['IPv6']
    if(brief):
        infos = {
            'Source': packet['IPv6'].src,
            'Destinaiton': packet['IPv6'].dst,
            'Length': len(packet),
            'Protocol': 'IPv6',
            'Info': packet.name
        }

        infos['Source'] = packet['IPv6'].src
        infos['Destinaiton'] = packet['IPv6'].dst

        if(packet.haslayer("DNS")):
            pkt_dns = packet['DNS']
            if(pkt_dns.qd is None):
                if(pkt_dns.ar is not None):
                    infos['Info'] = f'Standard query response: {pkt_dns.ar.rrname.decode()}'
                else:
                    infos['Info'] = f'Standard query response: {pkt_dns.an.rrname.decode()}'
            else:
                infos['Info'] = f'Standard query: {pkt_dns.qd.qname.decode()}'
        return infos
    else:
        header_dict = {
            58: 'ICMPv6',
            17: 'UDP',
        }
        infos_list = [
            {
                'brief_name': 'IPv6',
                'header': f'Internet Protocol Version 6, Src: {ipv6_layer.src}, Dst: {ipv6_layer.dst}',
                'childs': [
                    { 'header': f'Version: {ipv6_layer.version}'},
                    { 'header': f'Traffic Class: {hex(ipv6_layer.tc)}'},
                    { 'header': f'Flow Label: {hex(ipv6_layer.fl)}'},
                    { 'header': f'Payload Length: {ipv6_layer.plen}'},
                    { 'header': f'Next Header: {header_dict.get(ipv6_layer.nh, "unknow header")} {ipv6_layer.nh}'},
                    { 'header': f'Hop Limit: {ipv6_layer.hlim}'},
                    { 'header': f'Source Address: {ipv6_layer.src}'},
                    { 'header': f'Destination Address: {ipv6_layer.dst}'},
                ]
            }
        ]
        return infos_list

def handleUnknow(packet, brief):
    if(brief):
        infos = {
            'Source': packet.src,
            'Destinaiton': packet.dst,
            'Length': len(packet),
            'Protocol': hex(packet.type),
            'Info': packet.name
        }
        return infos
    else:
        return None

def analysis_network(packet, brief=True):
    
    if(packet.type == 0x800): # IPv4
        return handleIP(packet, brief)
    elif(packet.type == 0x806): # ARP
        return handleARP(packet, brief)
    elif(packet.type == 0x86dd): # IPv6
        return handleIpv6(packet, brief)
    elif(packet.type in [0x3200, 0x1E00, 0xE825]):
        return handleUnknow(packet, brief)
    else:
        packet.show()
        print(packet.type)
    
    return None