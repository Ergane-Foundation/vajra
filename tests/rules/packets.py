"""Build test traffic for the rule tests with scapy.

Everything here is generated, never captured, so the pcaps carry nobody's
real traffic. Timestamps are fixed so a run is the same every time.
"""

import ipaddress
import itertools

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6

SERVER = "10.0.0.10"
START = 1_700_000_000.0
MSS = 1400
_ports = itertools.count(40000)


def _ip(src, dst):
    if ipaddress.ip_address(src).version == 6:
        return IPv6(src=src, dst=dst)
    return IP(src=src, dst=dst)


def tcp_session(client, server, dport, request, response, start=START):
    """A complete TCP connection: handshake, one request, one response, close"""
    sport = next(_ports)
    out = _ip(client, server) / TCP(sport=sport, dport=dport)
    back = _ip(server, client) / TCP(sport=dport, dport=sport)
    c, s = 1000, 5000
    packets = [out.copy(), back.copy()]
    packets[0][TCP].flags, packets[0][TCP].seq = "S", c
    packets[1][TCP].flags, packets[1][TCP].seq, packets[1][TCP].ack = "SA", s, c + 1
    c, s = c + 1, s + 1

    def send(side, flags, payload=b""):
        packet = side.copy()
        packet[TCP].flags = flags
        if side is out:
            packet[TCP].seq, packet[TCP].ack = c, s
        else:
            packet[TCP].seq, packet[TCP].ack = s, c
        packets.append(packet / payload if payload else packet)

    send(out, "A")
    for i in range(0, len(request), MSS):
        send(out, "PA", request[i : i + MSS])
        c += len(request[i : i + MSS])
    send(back, "A")
    for i in range(0, len(response), MSS):
        send(back, "PA", response[i : i + MSS])
        s += len(response[i : i + MSS])
    send(out, "A")
    send(out, "FA")
    c += 1
    send(back, "FA")
    s += 1
    send(out, "A")
    for i, packet in enumerate(packets):
        packet.time = start + i * 0.001
    return packets


def http(client, path, method="GET", body=b"", server=SERVER, start=START):
    """One HTTP/1.1 request to port 80 and a 200 reply. `path` goes on the wire as written."""
    head = f"{method} {path} HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
    if body:
        head += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
    request = head.encode() + b"\r\n" + body
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
    return tcp_session(client, server, 80, request, response, start)


def ssh(client, server=SERVER, start=START):
    """An SSH connection that gets as far as the version exchange"""
    return tcp_session(client, server, 22, b"SSH-2.0-OpenSSH_9.6\r\n", b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n", start)


def dns(client, name, answer, server=SERVER, start=START):
    """An A query and its answer"""
    sport = next(_ports)
    query = _ip(client, server) / UDP(sport=sport, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname=name))
    reply = (
        _ip(server, client)
        / UDP(sport=53, dport=sport)
        / DNS(id=1, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=answer))
    )
    query.time, reply.time = start, start + 0.01
    return [query, reply]


def repeated(make, count, interval):
    """`count` copies of `make(start)`, started `interval` seconds apart"""
    return [packet for i in range(count) for packet in make(START + i * interval)]


def probes(client, dports, flags, gap=0.005, server=SERVER):
    """One bare TCP packet with `flags` to each port in turn, the way a scanner or SYN flood sends them"""
    packets = []
    for i, dport in enumerate(dports):
        packet = _ip(client, server) / TCP(sport=next(_ports), dport=dport, flags=flags, seq=1000)
        packet.time = START + i * gap
        packets.append(packet)
    return packets


def udp_stream(client, count, dport, gap, size=1200, new_port_each=False, server=SERVER):
    """`count` UDP datagrams of `size` bytes, from one socket like a VPN tunnel, or each from a new port"""
    sport = next(_ports)
    packets = []
    for i in range(count):
        if new_port_each:
            sport = next(_ports)
        packet = _ip(client, server) / UDP(sport=sport, dport=dport) / bytes(size)
        packet.time = START + i * gap
        packets.append(packet)
    return packets


def pings(client, count, gap, server=SERVER):
    """`count` ICMP echo requests"""
    packets = []
    for i in range(count):
        packet = IP(src=client, dst=server) / ICMP(type=8, id=7, seq=i) / bytes(56)
        packet.time = START + i * gap
        packets.append(packet)
    return packets
