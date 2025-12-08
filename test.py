#!/usr/bin/env python3
"""
Simple test script to show:
1. Suricata network flows from eve.json in real-time
2. Scapy packet capture with deep packet inspection

Press Ctrl+C to stop
"""

import json
import time
import os
import threading
from pathlib import Path
from datetime import datetime

# Check if scapy is available
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available - only showing Suricata flows")

# ANSI colors for terminal
class Color:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Color.BOLD}{Color.CYAN}{'='*70}{Color.RESET}")
    print(f"{Color.BOLD}{Color.CYAN}{text}{Color.RESET}")
    print(f"{Color.BOLD}{Color.CYAN}{'='*70}{Color.RESET}\n")

def watch_suricata_eve(eve_path):
    """Watch Suricata eve.json for network flows"""
    position = 0
    
    print(f"{Color.GREEN}📡 Watching Suricata flows: {eve_path}{Color.RESET}\n")
    
    while True:
        try:
            if not eve_path.exists():
                time.sleep(2)
                continue
            
            current_size = eve_path.stat().st_size
            
            if current_size < position:
                position = 0
            
            if current_size > position:
                with open(eve_path, 'r') as f:
                    f.seek(position)
                    
                    for line in f:
                        try:
                            event = json.loads(line.strip())
                            
                            # Show flows
                            if event.get('event_type') == 'flow':
                                print_flow(event)
                            
                            # Show alerts
                            elif event.get('event_type') == 'alert':
                                print_alert(event)
                            
                            # Show DNS
                            elif event.get('event_type') == 'dns':
                                print_dns(event)
                        
                        except json.JSONDecodeError:
                            pass
                    
                    position = f.tell()
            
            time.sleep(0.5)
        
        except Exception as e:
            print(f"{Color.RED}Error watching eve.json: {e}{Color.RESET}")
            time.sleep(1)

def print_flow(event):
    """Print network flow details"""
    timestamp = event.get('timestamp', '').split('T')[1][:8]
    src = f"{event.get('src_ip', '?')}:{event.get('src_port', '?')}"
    dst = f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}"
    proto = event.get('proto', '?')
    
    flow = event.get('flow', {})
    bytes_to = flow.get('bytes_toserver', 0)
    bytes_from = flow.get('bytes_toclient', 0)
    pkts_to = flow.get('pkts_toserver', 0)
    pkts_from = flow.get('pkts_toclient', 0)
    state = flow.get('state', 'unknown')
    reason = flow.get('reason', '')
    
    app_proto = event.get('app_proto', 'unknown')
    
    print(f"\n{Color.BOLD}{Color.BLUE}╔══ SURICATA FLOW ══════════════════════════════════════════════════╗{Color.RESET}")
    print(f"{Color.BLUE}║{Color.RESET} {Color.CYAN}Time:{Color.RESET} {timestamp}")
    print(f"{Color.BLUE}║{Color.RESET} {Color.CYAN}Flow:{Color.RESET} {src} {Color.YELLOW}→{Color.RESET} {dst} ({proto})")
    print(f"{Color.BLUE}║{Color.RESET} {Color.CYAN}App:{Color.RESET} {Color.BOLD}{app_proto.upper()}{Color.RESET}")
    print(f"{Color.BLUE}║{Color.RESET} {Color.CYAN}Stats:{Color.RESET} ↑{pkts_to} pkts/{bytes_to} bytes  ↓{pkts_from} pkts/{bytes_from} bytes")
    print(f"{Color.BLUE}║{Color.RESET} {Color.CYAN}State:{Color.RESET} {state} {f'({reason})' if reason else ''}")
    
    # Show HTTP details if available
    if 'http' in event:
        http = event['http']
        print(f"{Color.BLUE}║{Color.RESET} {Color.PURPLE}HTTP:{Color.RESET}")
        if 'hostname' in http:
            print(f"{Color.BLUE}║{Color.RESET}   Host: {http['hostname']}")
        if 'url' in http:
            print(f"{Color.BLUE}║{Color.RESET}   URL: {http.get('http_method', 'GET')} {http['url']}")
        if 'http_user_agent' in http:
            print(f"{Color.BLUE}║{Color.RESET}   User-Agent: {http['http_user_agent'][:50]}")
        if 'status' in http:
            print(f"{Color.BLUE}║{Color.RESET}   Status: {http['status']}")
    
    # Show TLS details if available
    if 'tls' in event:
        tls = event['tls']
        print(f"{Color.BLUE}║{Color.RESET} {Color.PURPLE}TLS:{Color.RESET}")
        if 'sni' in tls:
            print(f"{Color.BLUE}║{Color.RESET}   SNI: {tls['sni']}")
        if 'version' in tls:
            print(f"{Color.BLUE}║{Color.RESET}   Version: {tls['version']}")
        if 'ja3' in tls:
            print(f"{Color.BLUE}║{Color.RESET}   JA3: {tls['ja3']['hash']}")
    
    # Show DNS details if available
    if 'dns' in event:
        dns = event['dns']
        print(f"{Color.BLUE}║{Color.RESET} {Color.PURPLE}DNS:{Color.RESET}")
        if 'rrname' in dns:
            print(f"{Color.BLUE}║{Color.RESET}   Query: {dns['rrname']} ({dns.get('rrtype', 'A')})")
        if 'answers' in dns:
            for ans in dns['answers'][:3]:
                print(f"{Color.BLUE}║{Color.RESET}   Answer: {ans.get('rdata', 'N/A')}")
    
    print(f"{Color.BOLD}{Color.BLUE}╚═══════════════════════════════════════════════════════════════════╝{Color.RESET}")

def print_alert(event):
    """Print Suricata alert"""
    timestamp = event.get('timestamp', '').split('T')[1][:8]
    src = f"{event.get('src_ip', '?')}:{event.get('src_port', '?')}"
    dst = f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}"
    
    alert = event.get('alert', {})
    signature = alert.get('signature', 'Unknown')
    severity = alert.get('severity', 3)
    
    color = Color.RED if severity <= 2 else Color.YELLOW
    
    print(f"{color}[{timestamp}] ALERT{Color.RESET} "
          f"{Color.CYAN}{src}{Color.RESET} → {Color.GREEN}{dst}{Color.RESET} "
          f"{Color.BOLD}{signature}{Color.RESET}")

def print_dns(event):
    """Print DNS query"""
    timestamp = event.get('timestamp', '').split('T')[1][:8]
    dns = event.get('dns', {})
    query = dns.get('rrname', '?')
    qtype = dns.get('rrtype', '?')
    
    print(f"{Color.PURPLE}[{timestamp}] DNS  {Color.RESET} "
          f"{Color.CYAN}{event.get('src_ip', '?')}{Color.RESET} "
          f"query: {Color.BOLD}{query}{Color.RESET} ({qtype})")

def packet_callback(packet):
    """Scapy packet callback - deep packet inspection"""
    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            
            print(f"\n{Color.BOLD}{Color.GREEN}╔══ SCAPY PACKET INSPECTION ════════════════════════════════════════╗{Color.RESET}")
            print(f"{Color.GREEN}║{Color.RESET} {Color.CYAN}Time:{Color.RESET} {timestamp}")
            print(f"{Color.GREEN}║{Color.RESET} {Color.CYAN}IP:{Color.RESET} {src_ip} {Color.YELLOW}→{Color.RESET} {dst_ip} (TTL: {ttl})")
            print(f"{Color.GREEN}║{Color.RESET} {Color.CYAN}Size:{Color.RESET} {len(packet)} bytes")
            
            # TCP
            if TCP in packet:
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = str(tcp_layer.flags)
                seq = tcp_layer.seq
                ack = tcp_layer.ack
                window = tcp_layer.window
                
                print(f"{Color.GREEN}║{Color.RESET} {Color.PURPLE}TCP:{Color.RESET} {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                print(f"{Color.GREEN}║{Color.RESET}   Flags: {flags} | Seq: {seq} | Ack: {ack} | Window: {window}")
                
                # Check for HTTP
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if payload_str.startswith('HTTP') or any(method in payload_str[:20] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                            lines = payload_str.split('\r\n')[:5]
                            print(f"{Color.GREEN}║{Color.RESET} {Color.YELLOW}HTTP Payload:{Color.RESET}")
                            for line in lines:
                                if line.strip():
                                    print(f"{Color.GREEN}║{Color.RESET}   {line[:60]}")
                    except:
                        pass
                    
                    # Show hex dump of first 32 bytes
                    hex_dump = ' '.join(f'{b:02x}' for b in payload[:32])
                    if hex_dump:
                        print(f"{Color.GREEN}║{Color.RESET} {Color.YELLOW}Payload (hex):{Color.RESET} {hex_dump}")
            
            # UDP
            elif UDP in packet:
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                length = udp_layer.len
                
                print(f"{Color.GREEN}║{Color.RESET} {Color.PURPLE}UDP:{Color.RESET} {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                print(f"{Color.GREEN}║{Color.RESET}   Length: {length}")
                
                # Check for DNS
                if DNS in packet:
                    dns_layer = packet[DNS]
                    print(f"{Color.GREEN}║{Color.RESET} {Color.YELLOW}DNS:{Color.RESET}")
                    
                    if dns_layer.qd:  # Questions
                        for i in range(dns_layer.qdcount):
                            if hasattr(dns_layer.qd, 'qname'):
                                qname = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                                print(f"{Color.GREEN}║{Color.RESET}   Query: {qname}")
                    
                    if dns_layer.an:  # Answers
                        print(f"{Color.GREEN}║{Color.RESET}   Answers: {dns_layer.ancount}")
                        try:
                            for i in range(min(3, dns_layer.ancount)):
                                if hasattr(dns_layer.an, 'rdata'):
                                    print(f"{Color.GREEN}║{Color.RESET}   → {dns_layer.an.rdata}")
                        except:
                            pass
                
                # Check for DHCP (ports 67/68)
                elif src_port in [67, 68] or dst_port in [67, 68]:
                    print(f"{Color.GREEN}║{Color.RESET} {Color.YELLOW}Protocol:{Color.RESET} DHCP")
                
                # Check for NTP (port 123)
                elif src_port == 123 or dst_port == 123:
                    print(f"{Color.GREEN}║{Color.RESET} {Color.YELLOW}Protocol:{Color.RESET} NTP")
                
                # Check for mDNS (port 5353)
                elif src_port == 5353 or dst_port == 5353:
                    print(f"{Color.GREEN}║{Color.RESET} {Color.YELLOW}Protocol:{Color.RESET} mDNS")
                
                # Raw payload for other UDP
                elif Raw in packet:
                    payload = bytes(packet[Raw].load)
                    hex_dump = ' '.join(f'{b:02x}' for b in payload[:32])
                    if hex_dump:
                        print(f"{Color.GREEN}║{Color.RESET} {Color.YELLOW}Payload (hex):{Color.RESET} {hex_dump}")
            
            # ICMP
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                icmp_type = icmp_layer.type
                icmp_code = icmp_layer.code
                
                icmp_types = {
                    0: 'Echo Reply',
                    3: 'Destination Unreachable',
                    8: 'Echo Request',
                    11: 'Time Exceeded'
                }
                
                type_name = icmp_types.get(icmp_type, f'Type {icmp_type}')
                
                print(f"{Color.GREEN}║{Color.RESET} {Color.PURPLE}ICMP:{Color.RESET} {type_name} (Type: {icmp_type}, Code: {icmp_code})")
            
            # Other IP protocols
            else:
                proto = ip_layer.proto
                proto_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}
                proto_name = proto_names.get(proto, f'Protocol {proto}')
                print(f"{Color.GREEN}║{Color.RESET} {Color.PURPLE}Protocol:{Color.RESET} {proto_name}")
            
            print(f"{Color.BOLD}{Color.GREEN}╚═══════════════════════════════════════════════════════════════════╝{Color.RESET}")
        
        # ARP
        elif ARP in packet:
            arp_layer = packet[ARP]
            op = arp_layer.op
            op_name = 'Request' if op == 1 else 'Reply' if op == 2 else f'Op {op}'
            
            print(f"\n{Color.BOLD}{Color.PURPLE}╔══ SCAPY ARP PACKET ═══════════════════════════════════════════════╗{Color.RESET}")
            print(f"{Color.PURPLE}║{Color.RESET} {Color.CYAN}Time:{Color.RESET} {timestamp}")
            print(f"{Color.PURPLE}║{Color.RESET} {Color.CYAN}Type:{Color.RESET} {op_name}")
            print(f"{Color.PURPLE}║{Color.RESET} {Color.CYAN}Sender:{Color.RESET} {arp_layer.psrc} ({arp_layer.hwsrc})")
            print(f"{Color.PURPLE}║{Color.RESET} {Color.CYAN}Target:{Color.RESET} {arp_layer.pdst} ({arp_layer.hwdst})")
            print(f"{Color.BOLD}{Color.PURPLE}╚═══════════════════════════════════════════════════════════════════╝{Color.RESET}")
    
    except Exception as e:
        pass  # Silently ignore packet errors

def start_scapy_capture(interface=None):
    """Start Scapy packet capture"""
    if not SCAPY_AVAILABLE:
        return
    
    print(f"{Color.GREEN}🔍 Starting Scapy packet capture...{Color.RESET}")
    if interface:
        print(f"   Interface: {interface}")
    else:
        print(f"   Interface: default")
    print()
    
    try:
        # Capture packets (use store=False to avoid memory buildup)
        sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        print(f"{Color.RED}❌ Permission denied. Run with sudo:{Color.RESET}")
        print(f"   sudo python3 test.py")
    except Exception as e:
        print(f"{Color.RED}Scapy error: {e}{Color.RESET}")

def main():
    print_header("🔥 Suricata Flow + Scapy Packet Monitor")
    
    # Find eve.json
    eve_paths = [
        Path("/var/log/suricata/eve.json"),
        Path("/usr/local/var/log/suricata/eve.json"),
        Path("logs/eve.json"),
        Path("/opt/homebrew/var/log/suricata/eve.json")
    ]
    
    eve_path = None
    for path in eve_paths:
        if path.exists():
            eve_path = path
            break
    
    if not eve_path:
        print(f"{Color.YELLOW}⚠️  Suricata eve.json not found. Creating test file...{Color.RESET}")
        eve_path = Path("logs/eve.json")
        eve_path.parent.mkdir(exist_ok=True)
        eve_path.touch()
    
    print(f"{Color.CYAN}Suricata eve.json: {eve_path}{Color.RESET}")
    print(f"{Color.CYAN}Scapy available: {SCAPY_AVAILABLE}{Color.RESET}")
    print(f"\n{Color.YELLOW}Press Ctrl+C to stop{Color.RESET}\n")
    
    # Start Suricata watcher in thread
    suricata_thread = threading.Thread(target=watch_suricata_eve, args=(eve_path,), daemon=True)
    suricata_thread.start()
    
    # Small delay to let suricata thread start
    time.sleep(0.5)
    
    # Start Scapy capture (this will block until Ctrl+C)
    if SCAPY_AVAILABLE:
        try:
            start_scapy_capture()
        except KeyboardInterrupt:
            print(f"\n\n{Color.GREEN}✓ Stopped{Color.RESET}")
    else:
        # If no scapy, just keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Color.GREEN}✓ Stopped{Color.RESET}")

if __name__ == "__main__":
    main()
