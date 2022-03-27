

from struct import pack


def handleTCP(packet, infos):
    tcp_infos = packet['TCP']
    # print("#########" * 10)
    # print(dir(tcp_infos))
    # print(packet.layers())
    # print(packet.layers()[0])
    # print("#########" * 10)

    if(tcp_infos.dport == 80 or tcp_infos.sport == 80):
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
        flags = [tcp_infos.flags.A, tcp_infos.flags.R, tcp_infos.flags.S, tcp_infos.flags.F, tcp_infos.flags.U, tcp_infos.flags.P]
        msgs = ['ACK', 'RST', 'SYN', 'FIN', 'URG', 'PSH']
        msg = ', '.join([f'{msgs[i]}' for i, flag in enumerate(flags) if flag])
        infos['Info'] = f'{tcp_infos.sport} -> {tcp_infos.dport} [{msg}] Seq: {tcp_infos.seq}, ACK: {tcp_infos.ack}, WIN: {tcp_infos.window}'

def handleUDP(packet, infos):
    udp_infos = packet['UDP']
    infos['Protocol'] = 'UDP'
    infos['Info'] = f'{udp_infos.sport} -> {udp_infos.dport} length: {udp_infos.len}'

def handleICMP(packet, infos):
    infos['Protocol'] = 'ICMP'
    if packet.haslayer('ICMP'):
        icmp_infos = packet['ICMP']
        type_info_dict = {
            0: 'reply',
            8: 'request'
        }
        type_info = icmp_infos.type if icmp_infos.type not in type_info_dict else type_info_dict[icmp_infos.type]
        Info = f'Echo (ping) {type_info} id: {icmp_infos.id} seq: {icmp_infos.seq}'
    else:
        Info = 'No ICMP Layer'
    infos['Info'] = Info

def handleIGMP(packet, infos):
    infos['Protocol'] = 'IGMP'
    infos['Info'] = 'IGMP infos...'

def handleNone(packet, infos):
    protocol = packet['IP'].proto
    infos['Protocol'] = f'{protocol}'
    infos['Info'] = 'unknow infos...'

def handleProtocol(packet, protocol, infos):
    if(protocol == 6):
        handleTCP(packet, infos)
    elif(protocol == 17):
        handleUDP(packet, infos)
    elif(protocol == 1):
        handleICMP(packet, infos)
    elif(protocol == 2):
        handleIGMP(packet, infos)
    else:
        handleNone(packet, infos)

def handleIP(packet):
    infos = {
        'Source': packet['IP'].src,
        'Destinaiton': packet['IP'].dst,
        'Length': len(packet),
    }

    protocol = packet['IP'].proto

    handleProtocol(packet, protocol, infos)

    return infos

def handleARP(packet):

    arp_infos = packet['ARP']

    infos = {
        'Source': arp_infos.psrc,
        'Destinaiton': arp_infos.pdst,
        'Length': len(packet),
        'Protocol': 'ARP'
    }

    if(arp_infos.op == 1):
        # ASK
        Info = f'Who know {arp_infos.pdst}? Tell {arp_infos.psrc} please.'
    elif(arp_infos.op == 2):
        # Reply
        Info = f'{arp_infos.psrc} is at {arp_infos.hwsrc}'
    else:
        Info = f'ARP infos... {arp_infos.op}'

    infos['Info'] = Info

    return infos


def main(packet):
    # 数据链路层: IP or ARP
    if(packet.type == 0x800):
        return handleIP(packet)
    elif(packet.type == 0x806):
        return handleARP(packet)
    else:
        packet.show()
    
    return None