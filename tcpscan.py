import traceback
from common_modules import *
from banner_grab_sample_data import *

#TCP Configuration settings
tcp_timeout = 0.5

def tcp_syn_scan(dst_ip, dst_port_itr):
    rdm_seq_num = random.randint(0, 2**32 - 1)
    rdm_src_port = random.randint(32768, 61000)
    ip = IP(dst=dst_ip)

    res = []
    for port in dst_port_itr:
        try:
            syn_packet = TCP(sport=rdm_src_port, dport=port, flags='S', seq=rdm_seq_num)
            syn_ack_packet = sr1(ip/syn_packet, timeout=tcp_timeout)
            if syn_ack_packet == None:
                res.append({'Port':port, 'Status':'filtered', 'Service':socket.getservbyport(port)})
            elif (syn_ack_packet.haslayer(TCP)):
                flags = syn_ack_packet[TCP].flags

                # Check for SYN-ACK flag (port is open)
                if 'SA' == flags:
                    res.append({'Port':port, 'Status':'open', 'Service':socket.getservbyport(port)})
                elif 'R' in flags:
                    res.append({'Port':port, 'Status':'closed', 'Service':socket.getservbyport(port)})
                else:
                    res.append({'Port':port, 'Status':'filtered', 'Service':socket.getservbyport(port)})

            rdm_seq_num = random.randint(0, 2**32 - 1)
            rdm_src_port = random.randint(32768, 61000)
        except Exception as e:
            #Port service not found
            print(e)
            traceback.print_exc()
            continue
    return res

def buffer_resp(tcp_sock):
    buffer = b''
    response = b''
    while True:
        try:
            response = tcp_sock.recv(1024)
        except Exception as e:
            #In the case of a timeout, either the response is empty or partial data is retrieved. 
            print(e)
            if not response:
                break 
            else:
                buffer += response
    return buffer

#Use TCP sockets for full TCP handshake + Banner Grabbing for common ports
def tcp_full_scan(dst_ip, dst_port_itr):
    res = ''
    try:
        for port in dst_port_itr:
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            tcp_sock.settimeout(2)
            tcp_sock.connect((dst_ip, port))
            print(f'Connected to {dst_ip} at port {port}')

            data = buffer_resp(tcp_sock)
            #If data is empty, then test data is needed to generate banner
            if (not data):
                sample_data = banner_grab_sample_data(dst_ip, port)
                print('SAMPLE DATA READY')

                #Send sample data to server
                if (sample_data):
                    tcp_sock.send(sample_data)
                    data = tcp_sock.recv(2048)

                #If a response exists, parse it based on its port
                if (data):
                    res += parse_banner(data, port)
            tcp_sock.close()
    except Exception as e:
        print(e)
        traceback.print_exc()
    return res