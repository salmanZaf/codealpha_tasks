#!/usr/bin/env python3
"""
Network Traffic Packet Analyzer
================================
Captures and analyzes network packets using scapy or socket fallback.
Displays source/destination IPs, protocols, ports, and payload data.

Usage:
    sudo python3 packet_analyzer.py [OPTIONS]

Options:
    --interface, -i    Network interface (default: auto-detect)
    --count,     -c    Number of packets to capture (default: 50)
    --protocol,  -p    Filter by protocol: tcp|udp|icmp|all (default: all)
    --output,    -o    Save report to file (e.g. report.txt)
    --port,      --port Filter by port number
    --verbose,   -v    Show full payload content
    --summary,   -s    Show summary statistics only

Examples:
    sudo python3 packet_analyzer.py -c 100 -p tcp
    sudo python3 packet_analyzer.py -i eth0 -c 20 --port 80 -v
    sudo python3 packet_analyzer.py -c 50 -o capture_report.txt
"""

import sys
import os
import socket
import struct
import time
import argparse
import datetime
import json
import signal
from collections import defaultdict, Counter
from typing import Optional

# ─────────────────────────────────────────────
# ANSI Color Codes for Terminal Output
# ─────────────────────────────────────────────
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_DARK = "\033[40m"

    @staticmethod
    def disable():
        for attr in vars(Colors):
            if not attr.startswith("_") and attr != "disable":
                setattr(Colors, attr, "")

# ─────────────────────────────────────────────
# Protocol Mappings
# ─────────────────────────────────────────────
PROTOCOL_MAP = {
    1:   "ICMP",
    2:   "IGMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 143: "IMAP", 161: "SNMP", 194: "IRC",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-Sub", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6881: "BitTorrent",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

PROTOCOL_COLORS = {
    "TCP":    Colors.CYAN,
    "UDP":    Colors.GREEN,
    "ICMP":   Colors.YELLOW,
    "IGMP":   Colors.MAGENTA,
    "IPv6":   Colors.BLUE,
    "OTHER":  Colors.GRAY,
}

# ─────────────────────────────────────────────
# Packet Data Classes
# ─────────────────────────────────────────────
class EthernetFrame:
    def __init__(self, raw_data: bytes):
        self.raw = raw_data
        if len(raw_data) < 14:
            raise ValueError("Packet too short for Ethernet header")
        self.dest_mac   = self._format_mac(raw_data[:6])
        self.src_mac    = self._format_mac(raw_data[6:12])
        self.proto      = struct.unpack("!H", raw_data[12:14])[0]
        self.payload    = raw_data[14:]

    @staticmethod
    def _format_mac(raw: bytes) -> str:
        return ":".join(f"{b:02x}" for b in raw)

    @property
    def proto_name(self) -> str:
        return {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}.get(self.proto, f"0x{self.proto:04x}")


class IPv4Packet:
    def __init__(self, raw_data: bytes):
        if len(raw_data) < 20:
            raise ValueError("Packet too short for IPv4 header")
        version_ihl  = raw_data[0]
        self.version = (version_ihl >> 4)
        ihl          = (version_ihl & 0xF) * 4
        self.ttl     = raw_data[8]
        self.proto   = raw_data[9]
        self.src_ip  = socket.inet_ntoa(raw_data[12:16])
        self.dst_ip  = socket.inet_ntoa(raw_data[16:20])
        self.payload = raw_data[ihl:]
        self.length  = struct.unpack("!H", raw_data[2:4])[0]
        self.proto_name = PROTOCOL_MAP.get(self.proto, f"PROTO-{self.proto}")


class TCPSegment:
    def __init__(self, raw_data: bytes):
        if len(raw_data) < 20:
            raise ValueError("Packet too short for TCP header")
        self.src_port = struct.unpack("!H", raw_data[0:2])[0]
        self.dst_port = struct.unpack("!H", raw_data[2:4])[0]
        self.seq      = struct.unpack("!I", raw_data[4:8])[0]
        self.ack      = struct.unpack("!I", raw_data[8:12])[0]
        offset        = ((raw_data[12] >> 4) & 0xF) * 4
        flags_byte    = raw_data[13]
        self.flags    = {
            "FIN": bool(flags_byte & 0x01),
            "SYN": bool(flags_byte & 0x02),
            "RST": bool(flags_byte & 0x04),
            "PSH": bool(flags_byte & 0x08),
            "ACK": bool(flags_byte & 0x10),
            "URG": bool(flags_byte & 0x20),
        }
        self.payload  = raw_data[offset:]
        self.window   = struct.unpack("!H", raw_data[14:16])[0]

    @property
    def flags_str(self) -> str:
        return " ".join(k for k, v in self.flags.items() if v) or "NONE"

    @property
    def src_service(self) -> str:
        return WELL_KNOWN_PORTS.get(self.src_port, "")

    @property
    def dst_service(self) -> str:
        return WELL_KNOWN_PORTS.get(self.dst_port, "")


class UDPDatagram:
    def __init__(self, raw_data: bytes):
        if len(raw_data) < 8:
            raise ValueError("Packet too short for UDP header")
        self.src_port = struct.unpack("!H", raw_data[0:2])[0]
        self.dst_port = struct.unpack("!H", raw_data[2:4])[0]
        self.length   = struct.unpack("!H", raw_data[4:6])[0]
        self.payload  = raw_data[8:]

    @property
    def src_service(self) -> str:
        return WELL_KNOWN_PORTS.get(self.src_port, "")

    @property
    def dst_service(self) -> str:
        return WELL_KNOWN_PORTS.get(self.dst_port, "")


class ICMPPacket:
    TYPES = {
        0: "Echo Reply", 3: "Dest Unreachable", 4: "Source Quench",
        5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
        12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply",
    }
    def __init__(self, raw_data: bytes):
        if len(raw_data) < 4:
            raise ValueError("Packet too short for ICMP header")
        self.type    = raw_data[0]
        self.code    = raw_data[1]
        self.payload = raw_data[4:]
        self.type_name = self.TYPES.get(self.type, f"Type-{self.type}")


# ─────────────────────────────────────────────
# Statistics Tracker
# ─────────────────────────────────────────────
class PacketStats:
    def __init__(self):
        self.total       = 0
        self.protocols   = Counter()
        self.src_ips     = Counter()
        self.dst_ips     = Counter()
        self.src_ports   = Counter()
        self.dst_ports   = Counter()
        self.total_bytes = 0
        self.start_time  = time.time()
        self.conversations = Counter()  # (src_ip, dst_ip) pairs

    def record(self, proto: str, src_ip: str, dst_ip: str,
               src_port: Optional[int], dst_port: Optional[int], size: int):
        self.total       += 1
        self.total_bytes += size
        self.protocols[proto] += 1
        self.src_ips[src_ip]  += 1
        self.dst_ips[dst_ip]  += 1
        if src_port: self.src_ports[src_port] += 1
        if dst_port: self.dst_ports[dst_port] += 1
        self.conversations[(src_ip, dst_ip)] += 1

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def rate(self) -> float:
        e = self.elapsed
        return self.total / e if e > 0 else 0


# ─────────────────────────────────────────────
# Display / Formatting Helpers
# ─────────────────────────────────────────────
def format_payload(data: bytes, max_bytes: int = 64, verbose: bool = False) -> str:
    if not data:
        return f"{Colors.DIM}(no payload){Colors.RESET}"
    limit = len(data) if verbose else min(max_bytes, len(data))
    chunk = data[:limit]
    # Hex dump
    hex_part  = " ".join(f"{b:02x}" for b in chunk)
    # ASCII representation
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    suffix = f" ... +{len(data)-limit} more bytes" if len(data) > limit else ""
    return f"{Colors.GRAY}{hex_part}{Colors.RESET}  |  {Colors.DIM}{ascii_part}{suffix}{Colors.RESET}"


def port_label(port: int, service: str) -> str:
    if service:
        return f"{port}{Colors.DIM}({service}){Colors.RESET}"
    return str(port)


def proto_badge(proto: str) -> str:
    color = PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS["OTHER"])
    return f"{color}{Colors.BOLD}[{proto:5s}]{Colors.RESET}"


def separator(char: str = "─", width: int = 80) -> str:
    return f"{Colors.GRAY}{char * width}{Colors.RESET}"


def print_banner():
    banner = r"""
  ███╗   ██╗███████╗████████╗ ██████╗  █████╗ ██████╗ ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██╔══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ██║  ███╗███████║██████╔╝██║  ██║
  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║ ╚████║███████╗   ██║   ╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
    """
    subtitle = "  ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗"
    print(f"{Colors.CYAN}{Colors.BOLD}{banner}{Colors.RESET}")
    print(f"{Colors.CYAN}{'─'*68}{Colors.RESET}")
    print(f"{Colors.WHITE}  Network Traffic Packet Analyzer  |  Educational Tool  |  Python{Colors.RESET}")
    print(f"{Colors.CYAN}{'─'*68}{Colors.RESET}\n")


def print_packet(idx: int, ts: str, ip: IPv4Packet,
                 transport=None, payload: bytes = b"",
                 verbose: bool = False):
    proto_color = PROTOCOL_COLORS.get(ip.proto_name, PROTOCOL_COLORS["OTHER"])

    print(f"\n{separator()}")
    print(f"  {Colors.BOLD}#{idx:04d}{Colors.RESET}  "
          f"{Colors.GRAY}{ts}{Colors.RESET}  "
          f"{proto_badge(ip.proto_name)}  "
          f"{Colors.DIM}{ip.length} bytes  TTL={ip.ttl}{Colors.RESET}")

    # ── IP Layer ──────────────────────────────
    print(f"\n  {Colors.YELLOW}▶ IP Layer{Colors.RESET}")
    print(f"    Src: {Colors.GREEN}{ip.src_ip:>15}{Colors.RESET}   "
          f"Dst: {Colors.RED}{ip.dst_ip}{Colors.RESET}")

    # ── Transport Layer ───────────────────────
    if isinstance(transport, TCPSegment):
        t = transport
        print(f"\n  {Colors.CYAN}▶ TCP Layer{Colors.RESET}")
        print(f"    Src Port: {Colors.GREEN}{port_label(t.src_port, t.src_service):<22}{Colors.RESET} "
              f"Dst Port: {Colors.RED}{port_label(t.dst_port, t.dst_service)}{Colors.RESET}")
        print(f"    Flags   : {Colors.MAGENTA}{t.flags_str:<20}{Colors.RESET} "
              f"Window  : {t.window}")
        print(f"    Seq     : {Colors.DIM}{t.seq:<20}{Colors.RESET} "
              f"Ack     : {Colors.DIM}{t.ack}{Colors.RESET}")
        payload = t.payload

    elif isinstance(transport, UDPDatagram):
        u = transport
        print(f"\n  {Colors.GREEN}▶ UDP Layer{Colors.RESET}")
        print(f"    Src Port: {Colors.GREEN}{port_label(u.src_port, u.src_service):<22}{Colors.RESET} "
              f"Dst Port: {Colors.RED}{port_label(u.dst_port, u.dst_service)}{Colors.RESET}")
        print(f"    Length  : {u.length}")
        payload = u.payload

    elif isinstance(transport, ICMPPacket):
        ic = transport
        print(f"\n  {Colors.YELLOW}▶ ICMP Layer{Colors.RESET}")
        print(f"    Type: {Colors.YELLOW}{ic.type_name:<30}{Colors.RESET} Code: {ic.code}")
        payload = ic.payload

    # ── Payload ───────────────────────────────
    if payload:
        print(f"\n  {Colors.MAGENTA}▶ Payload ({len(payload)} bytes){Colors.RESET}")
        print(f"    {format_payload(payload, verbose=verbose)}")

        # Try to detect HTTP
        try:
            decoded = payload.decode("utf-8", errors="replace")
            if decoded.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HTTP/")):
                first_line = decoded.split("\n")[0].strip()
                print(f"    {Colors.BOLD}{Colors.CYAN}HTTP → {first_line}{Colors.RESET}")
            elif decoded.startswith("DNS") or (len(payload) > 2 and payload[2] & 0x80):
                print(f"    {Colors.BOLD}{Colors.GREEN}[Possible DNS response]{Colors.RESET}")
        except Exception:
            pass


def print_summary(stats: PacketStats):
    print(f"\n\n{separator('═')}")
    print(f"{Colors.BOLD}{Colors.WHITE}  CAPTURE SUMMARY{Colors.RESET}")
    print(separator('═'))

    elapsed = stats.elapsed
    print(f"\n  {Colors.CYAN}Duration  :{Colors.RESET} {elapsed:.2f}s")
    print(f"  {Colors.CYAN}Packets   :{Colors.RESET} {stats.total}")
    print(f"  {Colors.CYAN}Total Data:{Colors.RESET} {stats.total_bytes:,} bytes ({stats.total_bytes/1024:.1f} KB)")
    print(f"  {Colors.CYAN}Rate      :{Colors.RESET} {stats.rate:.1f} pkt/s")

    # Protocol breakdown
    print(f"\n  {Colors.YELLOW}Protocol Breakdown:{Colors.RESET}")
    for proto, count in stats.protocols.most_common():
        pct  = count / stats.total * 100
        bar  = "█" * int(pct / 2)
        color = PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS["OTHER"])
        print(f"    {color}{proto:<8}{Colors.RESET}  {bar:<50} {count:>4} ({pct:5.1f}%)")

    # Top talkers
    print(f"\n  {Colors.YELLOW}Top Source IPs:{Colors.RESET}")
    for ip, count in stats.src_ips.most_common(5):
        print(f"    {Colors.GREEN}{ip:<17}{Colors.RESET}  {count:>4} packets")

    print(f"\n  {Colors.YELLOW}Top Destination IPs:{Colors.RESET}")
    for ip, count in stats.dst_ips.most_common(5):
        print(f"    {Colors.RED}{ip:<17}{Colors.RESET}  {count:>4} packets")

    # Top ports
    if stats.dst_ports:
        print(f"\n  {Colors.YELLOW}Top Destination Ports:{Colors.RESET}")
        for port, count in stats.dst_ports.most_common(5):
            svc = WELL_KNOWN_PORTS.get(port, "")
            label = f"{port}" + (f" ({svc})" if svc else "")
            print(f"    {Colors.CYAN}{label:<22}{Colors.RESET}  {count:>4} packets")

    # Top conversations
    if stats.conversations:
        print(f"\n  {Colors.YELLOW}Top Conversations:{Colors.RESET}")
        for (src, dst), count in stats.conversations.most_common(5):
            print(f"    {Colors.GREEN}{src:<17}{Colors.RESET} → {Colors.RED}{dst:<17}{Colors.RESET}  {count:>4} packets")

    print(f"\n{separator('═')}\n")


# ─────────────────────────────────────────────
# Core Capture Engine (raw socket)
# ─────────────────────────────────────────────
class PacketCapture:
    def __init__(self, interface: Optional[str] = None,
                 count: int = 50,
                 proto_filter: str = "all",
                 port_filter: Optional[int] = None,
                 verbose: bool = False,
                 output_file: Optional[str] = None,
                 summary_only: bool = False):
        self.interface    = interface
        self.count        = count
        self.proto_filter = proto_filter.upper()
        self.port_filter  = port_filter
        self.verbose      = verbose
        self.output_file  = output_file
        self.summary_only = summary_only
        self.stats        = PacketStats()
        self.captured     = []
        self._running     = True

    def _port_matches(self, transport) -> bool:
        if self.port_filter is None:
            return True
        if isinstance(transport, (TCPSegment, UDPDatagram)):
            return (transport.src_port == self.port_filter or
                    transport.dst_port == self.port_filter)
        return True

    def _proto_matches(self, proto_name: str) -> bool:
        if self.proto_filter in ("ALL", ""):
            return True
        return proto_name.upper() == self.proto_filter

    def start(self):
        # Requires root / administrator
        try:
            if sys.platform == "win32":
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                host = socket.gethostbyname(socket.gethostname())
                sock.bind((host, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux/macOS: ETH_P_ALL = 3
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.htons(0x0003))
                if self.interface:
                    sock.bind((self.interface, 0))
        except PermissionError:
            print(f"{Colors.RED}{Colors.BOLD}[ERROR] Root/Administrator privileges required.{Colors.RESET}")
            print(f"  Run: {Colors.YELLOW}sudo python3 packet_analyzer.py{Colors.RESET}\n")
            sys.exit(1)
        except OSError as e:
            print(f"{Colors.RED}[ERROR] Could not open raw socket: {e}{Colors.RESET}")
            sys.exit(1)

        signal.signal(signal.SIGINT, self._handle_sigint)

        print(f"  {Colors.GREEN}●{Colors.RESET} Listening on "
              f"{Colors.BOLD}{self.interface or 'all interfaces'}{Colors.RESET}  "
              f"| Proto: {Colors.BOLD}{self.proto_filter}{Colors.RESET}  "
              f"| Capturing {Colors.BOLD}{self.count}{Colors.RESET} packets\n"
              f"  {Colors.DIM}Press Ctrl+C to stop early{Colors.RESET}\n")

        pkt_idx = 0
        while self._running and pkt_idx < self.count:
            try:
                raw, addr = sock.recvfrom(65535)
            except Exception:
                break

            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

            try:
                # Linux raw sockets include Ethernet header
                if sys.platform != "win32":
                    eth = EthernetFrame(raw)
                    if eth.proto != 0x0800:     # Only IPv4 for now
                        continue
                    ip_raw = eth.payload
                else:
                    ip_raw = raw

                ip = IPv4Packet(ip_raw)

                if not self._proto_matches(ip.proto_name):
                    continue

                transport = None
                payload   = b""

                if ip.proto == 6:    # TCP
                    transport = TCPSegment(ip.payload)
                elif ip.proto == 17: # UDP
                    transport = UDPDatagram(ip.payload)
                elif ip.proto == 1:  # ICMP
                    transport = ICMPPacket(ip.payload)
                else:
                    payload = ip.payload

                if not self._port_matches(transport):
                    continue

                # Record stats
                src_port = getattr(transport, "src_port", None)
                dst_port = getattr(transport, "dst_port", None)
                self.stats.record(ip.proto_name, ip.src_ip, ip.dst_ip,
                                  src_port, dst_port, len(raw))

                pkt_idx += 1

                if not self.summary_only:
                    print_packet(pkt_idx, ts, ip, transport, payload, self.verbose)

                # Store for JSON export
                self.captured.append({
                    "id": pkt_idx,
                    "timestamp": ts,
                    "src_ip": ip.src_ip,
                    "dst_ip": ip.dst_ip,
                    "protocol": ip.proto_name,
                    "ttl": ip.ttl,
                    "length": ip.length,
                    "src_port": src_port,
                    "dst_port": dst_port,
                })

            except Exception as e:
                if self.verbose:
                    print(f"{Colors.GRAY}  [parse error] {e}{Colors.RESET}")
                continue

        sock.close()
        if sys.platform == "win32":
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass

        print_summary(self.stats)
        self._save_report()

    def _handle_sigint(self, sig, frame):
        print(f"\n\n  {Colors.YELLOW}[!] Capture interrupted by user{Colors.RESET}")
        self._running = False

    def _save_report(self):
        if not self.output_file:
            return
        data = {
            "meta": {
                "captured_at": datetime.datetime.now().isoformat(),
                "total_packets": self.stats.total,
                "total_bytes": self.stats.total_bytes,
                "duration_s": round(self.stats.elapsed, 3),
                "interface": self.interface or "all",
            },
            "protocol_breakdown": dict(self.stats.protocols),
            "top_src_ips": dict(self.stats.src_ips.most_common(10)),
            "top_dst_ips": dict(self.stats.dst_ips.most_common(10)),
            "top_dst_ports": {
                f"{p}({WELL_KNOWN_PORTS.get(p,'')})": c
                for p, c in self.stats.dst_ports.most_common(10)
            },
            "packets": self.captured,
        }
        with open(self.output_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  {Colors.GREEN}✓ Report saved to:{Colors.RESET} {Colors.BOLD}{self.output_file}{Colors.RESET}\n")


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer — capture & analyze traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=50,
                        help="Number of packets to capture (default: 50)")
    parser.add_argument("-p", "--protocol", default="all",
                        choices=["all", "tcp", "udp", "icmp", "TCP", "UDP", "ICMP"],
                        help="Protocol filter (default: all)")
    parser.add_argument("-o", "--output", default=None,
                        help="Save JSON report to file")
    parser.add_argument("--port", type=int, default=None,
                        help="Filter by port number")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show full payload content")
    parser.add_argument("-s", "--summary", action="store_true",
                        help="Show summary only (no per-packet output)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.no_color:
        Colors.disable()

    print_banner()

    capture = PacketCapture(
        interface=args.interface,
        count=args.count,
        proto_filter=args.protocol,
        port_filter=args.port,
        verbose=args.verbose,
        output_file=args.output,
        summary_only=args.summary,
    )
    capture.start()


if __name__ == "__main__":
    main()
