import argparse
import urllib.request
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6


AS_REGEX = re.compile(r'"origin": "(\d+?)",')


def get_asn(ip):
    link = ('https://stat.ripe.net/data/routing-status/data.json?resource='
            f'{ip}')
    with urllib.request.urlopen(link) as page:
        result = AS_REGEX.search(page.read().decode())
        if result:
            return result[1]
        return "--"


def get_ip_pkt(ip, i):
    if ':' in ip:
        return IPv6(dst=ip, hlim=i)
    return IP(dst=ip, ttl=i)


def get_route(ip_addr, max_q, proto, timeout, port=0, is_v=False):
    protos = {'udp': UDP(dport=port), 'tcp': TCP(dport=port, flags='S'),
              'icmp': ICMP()}

    for i in range(1, max_q + 1):
        time_start = time.time()
        reply = sr1(get_ip_pkt(ip_addr, i) / protos[proto], verbose=0,
                    timeout=timeout)
        if reply is None:
            print(f"{i}. *")
            continue
        else:
            result = f"{i}.  {reply.src.ljust(15, ' ')}   " \
                     f"{str((reply.time - time_start) * 1000)[:5]}"
            if is_v:
                asn = get_asn(reply.src)
                if asn is not None:
                    result = f"{result}      {asn}"
            print(result)

        if reply.src == ip_addr:
            break


def main():
    args = argparse.ArgumentParser(prog='traceroute',
                                   usage='%(prog)s '
                                         '[OPTIONS] IP_ADDRESS {tcp|udp|icmp}')
    args.add_argument('-t', type=int, action='store', nargs='?',
                      default=2, help='таймаут ожидания ответа '
                                      '(по умолчанию 2с)')
    args.add_argument('-p', type=int, action='store', nargs='?', default=0,
                      help='порт (для tcp или udp)')
    args.add_argument('-n', type=int, action='store', nargs='?', default=20,
                      help='максимальное количество запросов')
    args.add_argument('-v', action='store_true',
                      help='вывод номера автономной системы '
                           'для каждого ip-адреса')

    args.add_argument('IP_ADDRESS', type=str,
                      help='ip-адрес')

    args.add_argument('PROTO', choices=['tcp', 'udp', 'icmp'],
                      help='протокол')

    args = args.parse_args()

    dest_ip = args.IP_ADDRESS
    header = '№   IP' + ' '*16 + 'TIME,ms    '
    if args.v:
        header += 'AS'
    print(header)

    get_route(dest_ip, args.n, args.PROTO, args.t, args.p, args.v)


if __name__ == '__main__':
    main()
