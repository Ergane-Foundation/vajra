"""Build test traffic for the rule tests with scapy.

Everything here is generated, never captured, so the pcaps carry nobody's
real traffic. Timestamps are fixed so a run is the same every time.
"""

import ipaddress
import itertools

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

SERVER = "10.0.0.10"
START = 1_700_000_000.0
_ports = itertools.count(40000)


def _ip(src, dst):
    if ipaddress.ip_address(src).version == 6:
        return IPv6(src=src, dst=dst)
    return IP(src=src, dst=dst)


def tcp_session(client, server, dport, request, response, start=START):
    """A complete TCP connection: handshake, one request, one response, close"""
    sport = next(_ports)
    c, s = 1000, 5000
    out = _ip(client, server)
    back = _ip(server, client)
    packets = [
        out / TCP(sport=sport, dport=dport, flags="S", seq=c),
        back / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1),
        out / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1),
        out / TCP(sport=sport, dport=dport, flags="PA", seq=c + 1, ack=s + 1) / request,
        back / TCP(sport=dport, dport=sport, flags="A", seq=s + 1, ack=c + 1 + len(request)),
        back / TCP(sport=dport, dport=sport, flags="PA", seq=s + 1, ack=c + 1 + len(request)) / response,
        out / TCP(sport=sport, dport=dport, flags="A", seq=c + 1 + len(request), ack=s + 1 + len(response)),
        out / TCP(sport=sport, dport=dport, flags="FA", seq=c + 1 + len(request), ack=s + 1 + len(response)),
        back / TCP(sport=dport, dport=sport, flags="FA", seq=s + 1 + len(response), ack=c + 2 + len(request)),
        out / TCP(sport=sport, dport=dport, flags="A", seq=c + 2 + len(request), ack=s + 2 + len(response)),
    ]
    for i, packet in enumerate(packets):
        packet.time = start + i * 0.001
    return packets


def http(client, path, method="GET", body=b"", server=SERVER):
    """One HTTP/1.1 request to port 80 and a 200 reply. `path` goes on the wire as written."""
    head = f"{method} {path} HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
    if body:
        head += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
    request = head.encode() + b"\r\n" + body
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
    return tcp_session(client, server, 80, request, response)


def ssh(client, server=SERVER):
    """An SSH connection that gets as far as the version exchange"""
    return tcp_session(client, server, 22, b"SSH-2.0-OpenSSH_9.6\r\n", b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n")


def dns(client, name, answer, server=SERVER):
    """An A query and its answer"""
    sport = next(_ports)
    query = _ip(client, server) / UDP(sport=sport, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname=name))
    reply = (
        _ip(server, client)
        / UDP(sport=53, dport=sport)
        / DNS(id=1, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=answer))
    )
    query.time, reply.time = START, START + 0.01
    return [query, reply]
