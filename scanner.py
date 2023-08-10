from tcpscan import *

def parse_port_spec(dst_port_spec):
    port_itr = []
    try:
        dst_port_spec = str(dst_port_spec)
        if '-' in dst_port_spec:
            start, end = map(int, dst_port_spec.split('-'))
            port_itr = range(start, end+1)
        elif ',' in dst_port_spec:
            port_itr = map(int, dst_port_spec.split(','))
        else:
            port_itr.append(int(dst_port_spec))
        return list(port_itr)
    except Exception as e:
        print(e)


def scan_port(dst_ip, dst_port_spec, type):
    port_itr = parse_port_spec(dst_port_spec)
    #Disallow invalid ports
    for port in port_itr:
        try:
            if not (0 <= port <= 65535):
                raise Exception("Please provide valid port specifications (0 to 65535)")
        except Exception as e:
            print(e)
            return

    res = None
    #TCP SYN Scan
    if (type == 'tcp-syn'):
        print('\ntcp-syn scanning ' + dst_ip + '...')
        res = tcp_syn_scan(dst_ip, port_itr)
        if res:
            print('{:<10}{:<10}{:<15}'.format('Port', 'Status', 'Service'))
            print('-' * 35)
            for entry in res:
                print('{:<10}{:<10}{:<15}'.format(entry['Port'], entry['Status'], entry['Service']))
    #Full TCP Scan + Banner Grabbing
    elif (type == 'tcp-full'):
        print('tcp-full scanning ' + dst_ip + '...\n')
        res = tcp_full_scan(dst_ip, port_itr)

#Currently does not support scanning on current host and remote devices behind a NAT router.
def main():
   scan_port('192.168.1.1', '80, 443, 22, 110', 'tcp-syn')

if __name__ == '__main__':
   main()
