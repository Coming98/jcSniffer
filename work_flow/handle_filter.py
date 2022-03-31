from scapy.all import IP
import copy

def get_proto_list(window, data):
    if(data == '*'): return True, ['*', ]
    proto_list = [item.strip().upper() for item in data.split(',') ]

    for item in proto_list:
        if(item not in window.support_protocol_list):
            return False, f'{item} protocol not support by now.'
    return True, proto_list


def get_port_list(data):
    port_list = []

    port_patterns = [item.strip() for item in data.split(',')]
    for pattern in port_patterns:
        if('-' in pattern):
            infos = [item.strip() for item in pattern.split('-')]
            if(len(infos) != 2 or not infos[0].isdigit() or not infos[1].isdigit()): return f"Wrong Port Range: {pattern}"
            start, end = int(infos[0]), int(infos[1])
            port_list.extend(list(range(start, end + 1)))
        else:
            if(pattern == '*'): return True, ['*', ]
            if(not pattern.isdigit()): return False, f"Wrong Port Number: {pattern}"
            port_list.append(int(pattern))
    return True, port_list

def get_ip_list(data):
    if(data == '*'): return True, ['*', ]
    try:
        ips = IP(src=data).src
        if(type(ips) == str):
            ips = [ips, ]
        ip_list = list(ips)
        return True, ip_list
    except:
        return False, f"Wrong IP {data}"

def process_filter_chain(window, filter, split):
    infos = [ item.strip() for item in filter.split(split) ]

    if(len(infos) != 3): return False, f"Wrong Chain Pattern: {filter}"

    if(':' in infos[0]): 
        src_infos = infos[0].split(':')
        if(len(src_infos) != 2): return False, f"Wrong Chain Pattern: {infos[0]}"
        src_ip, src_port = src_infos

        flag = get_port_list(src_infos[1])
        if(flag[0] == False): return flag
        src_port = flag[1]
    else:
        src_ip = infos[0]
        src_port = []

    flag = get_ip_list(src_ip)
    if(flag[0] == False): return flag
    src_ip = flag[1]
        

    proto = infos[1]
    flag = get_proto_list(window, proto)
    if(flag[0] == False): return flag
    proto_list = flag[1]

    if(':' in infos[2]): 
        dst_infos = infos[2].split(':')
        if(len(dst_infos) != 2): return False, f"Wrong Chain Pattern: {infos[2]}"
        dst_ip, dst_port = dst_infos

        flag = get_port_list(dst_infos[1])
        if(flag[0] == False): return flag
        dst_port = flag[1]
    else:
        dst_ip = infos[2]
        dst_port = []

    flag = get_ip_list(dst_ip)
    if(flag[0] == False): return flag
    dst_ip = flag[1]

    return True, (src_ip, src_port, proto_list, dst_ip, dst_port)
    
def handle_filter_chain(window, filter, limit_dict):
    if('<>' in filter):
        flag = process_filter_chain(window, filter, split='<>')

        if(flag[0] == False): return flag
        sip, sport, protocol, dip, dport = flag[1]
        limit_dict_reverse = copy.deepcopy(limit_dict)
        limit_dict['src'].extend(sip)
        limit_dict['dst'].extend(dip)
        limit_dict['sport'].extend(sport)
        limit_dict['dport'].extend(dport)
        limit_dict['protocol'].extend(protocol)

        limit_dict_reverse['src'].extend(dip)
        limit_dict_reverse['dst'].extend(sip)
        limit_dict_reverse['sport'].extend(dport)
        limit_dict_reverse['dport'].extend(sport)
        limit_dict_reverse['protocol'].extend(protocol)
        return True, limit_dict_reverse
    elif('>' in filter):
        flag = process_filter_chain(window, filter, split='>')
        if(flag[0] == False): return flag
        sip, sport, protocol, dip, dport = flag[1]
        limit_dict['src'].extend(sip)
        limit_dict['dst'].extend(dip)
        limit_dict['sport'].extend(sport)
        limit_dict['dport'].extend(dport)
        limit_dict['protocol'].extend(protocol)
    elif('<' in filter):
        flag = process_filter_chain(window, filter, split='>')
        if(flag[0] == False): return flag
        dip, dport, protocol, sip, sport = flag[1]
        limit_dict['src'].extend(sip)
        limit_dict['dst'].extend(dip)
        limit_dict['sport'].extend(sport)
        limit_dict['dport'].extend(dport)
        limit_dict['protocol'].extend(protocol)
    else:
        return False, f"Wrong Chain Pattern {filter}"
    return True, None

def handle_filter_single(window, filter, limit_dict):
    infos = filter.split('=')
    if(len(infos) >= 3 or len(infos) <= 1): return False, f"Wrong single filter: {filter}"
    cmd, data = infos
    if(cmd == 'pro'):
        flag = get_proto_list(window, data)
        if(flag[0] == False): return flag
        limit_dict['protocol'].extend(flag[1])
    elif(cmd in ['sport', 'dport', 'port']):
        flag = get_port_list(data)
        
        if(flag[0] == False): return flag
        limit_dict[cmd].extend(flag[1])
    elif(cmd in ['src', 'dst', 'ip']):
        flag = get_ip_list(data)
        
        if(flag[0] == False): return flag
        limit_dict[cmd].extend(flag[1])
    else:
        return False, f'Wrong input: {cmd}'
    return True, None
def handle_filter_item(window, filter, limit_dict):
    if('<>' in filter or '>' in filter or '>' in filter):
        return handle_filter_chain(window, filter, limit_dict)
    else:
        return handle_filter_single(window, filter, limit_dict)

def update_filter(window, filter):
    filter_list = [item.strip() for item in filter.split('OR') ]
    limit_filters = []

    for filter in filter_list:
        limit_dict = {
            'protocol': [],
            'sport': [],
            'dport': [],
            'port': [],
            'src': [],
            'dst': [],
            'ip': [],
        }
        flag = handle_filter_item(window, filter, limit_dict)

        if(flag[0] == False): 
            return flag

        for key, value in limit_dict.items():
            if('*' in value):
                limit_dict[key] = ['*', ]
        limit_filters.append(limit_dict)

        limit_filters_reverse = flag[1]
        if(limit_filters_reverse is not None):
            for key, value in limit_filters_reverse.items():
                if('*' in value):
                    limit_filters_reverse[key] = ['*', ]
            limit_filters.append(limit_filters_reverse)
    print(limit_filters)
    return True, limit_filters
    
    # update filter and update table