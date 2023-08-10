import re

def banner_grab_sample_data(dst_ip, port):
    sample_data = {
        80: b'''GET / HTTP/1.1\r
Host: ''' + (dst_ip.encode()) + b'''\r
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r
Accept-Language: en-US,en;q=0.5\r
Accept-Encoding: gzip, deflate\r
Connection: close\r
Upgrade-Insecure-Requests: 1\r
\r\n
''',
        443: b'''
GET / HTTP/1.1\r
Host: ''' + (dst_ip.encode()) + b'''\r
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r
Accept-Language: en-US,en;q=0.5\r
Accept-Encoding: gzip, deflate\r
Connection: close\r
Upgrade-Insecure-Requests: 1\r
'''
    }

    if port in sample_data:
        return sample_data[port]
    else:
        return None

def http_banner_parser(raw_http_resp):
    res = ''
    data = raw_http_resp.decode()
    http_version_match = re.search('^HTTP/\d[.]\d', data, re.IGNORECASE)
    server_info_match = re.search('Server: ([^\r\n]+)', data, re.IGNORECASE)

    #If found, add these information to result
    if (http_version_match):
        res += 'Version: ' + http_version_match.group() + '\n'

    if (server_info_match):
        res += 'Web Server: ' + server_info_match.group()[8:] + '\n'
    return res

def parse_banner(raw_data, dst_port):
    if (dst_port == 80 or dst_port == 443):
        return http_banner_parser(raw_data)
    