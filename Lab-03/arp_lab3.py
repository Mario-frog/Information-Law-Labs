"""Lab 3 — ARP research. Run only in a network you own or administer."""
import argparse
import ipaddress
import platform
import socket
import struct
import time
from collections import defaultdict


def local_scan(network, timeout=2):
    from scapy.all import ARP, Ether, srp
    cidr = ipaddress.ip_network(network, strict=False)
    if not cidr.is_private or cidr.num_addresses > 256:
        raise ValueError('Only private subnets of up to 256 addresses are supported.')
    answers, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=str(cidr)),
                     timeout=timeout, verbose=False)
    hosts = sorted({(p.psrc, p.hwsrc.lower()) for _, p in answers},
                   key=lambda item: int(ipaddress.ip_address(item[0])))
    return hosts


def print_hosts(hosts):
    print(f'{"IP":<18} MAC')
    print('-' * 38)
    for ip, mac in hosts:
        print(f'{ip:<18} {mac}')
    print(f'Active devices: {len(hosts)}')


def plot_hosts(hosts, filename):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import networkx as nx
    graph = nx.Graph()
    for ip, mac in hosts:
        graph.add_node(ip, bipartite=0)
        graph.add_node(mac, bipartite=1)
        graph.add_edge(ip, mac)
    fig, ax = plt.subplots(figsize=(11, max(4, len(hosts)*0.65)))
    if hosts:
        pos = {ip: (0, i) for i, (ip, _) in enumerate(hosts)}
        pos.update({mac: (1, i) for i, (_, mac) in enumerate(hosts)})
        nx.draw_networkx(graph, pos, ax=ax, node_size=1100, font_size=8,
                         node_color='#dae8f5', edge_color='#69849b')
        ax.set_xlim(-0.4, 1.4)
    else:
        ax.text(0.5, 0.5, 'No ARP replies', ha='center', va='center')
    ax.axis('off')
    fig.tight_layout()
    fig.savefig(filename, dpi=170)
    plt.close(fig)
    print(f'Saved graph: {filename}')


def monitor(seconds, iface=None):
    from scapy.all import ARP, sniff
    seen = defaultdict(set)
    def handle(pkt):
        if not pkt.haslayer(ARP):
            return
        p = pkt[ARP]
        ip, mac = p.psrc, p.hwsrc.lower()
        if not ip or ip == '0.0.0.0':
            return
        if mac not in seen[ip] and seen[ip]:
            print(f'[WARNING] {ip}: previously {sorted(seen[ip])}, now {mac}')
        seen[ip].add(mac)
        print(f'ARP op={p.op}: {ip} -> {mac}')
    print(f'Listening for ARP for {seconds} seconds (Ctrl+C to stop)')
    sniff(filter='arp', prn=handle, store=False, timeout=seconds, iface=iface)
    print('Note: IP/MAC changes can be legitimate; investigate any alerts.')


def _mac_bytes(text):
    return bytes.fromhex(text.replace(':', '').replace('-', ''))


def raw_arp_request(interface, source_ip, target_ip, source_mac, timeout=3):
    """Make Ethernet + ARP request manually with struct and Linux AF_PACKET socket."""
    if platform.system() != 'Linux':
        raise OSError('AF_PACKET raw Ethernet sockets require Linux; use scan on Windows.')
    ipaddress.IPv4Address(source_ip)
    ipaddress.IPv4Address(target_ip)
    srcmac = _mac_bytes(source_mac)
    if len(srcmac) != 6:
        raise ValueError('MAC must be 6 bytes')
    eth = b'\xff'*6 + srcmac + struct.pack('!H', 0x0806)
    arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
    arp += srcmac + socket.inet_aton(source_ip) + b'\x00'*6 + socket.inet_aton(target_ip)
    frame = eth + arp
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as s:
        s.bind((interface, 0))
        s.settimeout(timeout)
        s.send(frame)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data = s.recv(65535)
            except socket.timeout:
                break
            if len(data) < 42 or data[12:14] != b'\x08\x06':
                continue
            operation = struct.unpack('!H', data[20:22])[0]
            remote_ip = socket.inet_ntoa(data[28:32])
            if operation == 2 and remote_ip == target_ip:
                mac = ':'.join(f'{b:02x}' for b in data[22:28])
                print(f'ARP reply: {target_ip} -> {mac}')
                return mac
    print('No ARP reply received')
    return None


def demo_detection():
    sample = [('192.168.1.1', 'aa:bb:cc:00:00:01'),
              ('192.168.1.15', 'aa:bb:cc:00:00:15'),
              ('192.168.1.1', 'aa:bb:cc:00:00:99')]
    mapping = {}
    for ip, mac in sample:
        if ip in mapping and mapping[ip] != mac:
            print(f'[WARNING] {ip}: {mapping[ip]} -> {mac}')
        else:
            print(f'[OBSERVED] {ip}: {mac}')
        mapping[ip] = mac
    print('Demo uses synthetic data; no packets were transmitted.')


def main():
    p = argparse.ArgumentParser(description='Lab 3 ARP scanner, graph and change detector')
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('scan', help='ARP scan a private subnet')
    s.add_argument('network', help='e.g. 192.168.1.0/24')
    s.add_argument('--graph', default='arp_network.png')
    m = sub.add_parser('monitor', help='Detect IP/MAC changes in observed ARP frames')
    m.add_argument('--seconds', type=int, default=30)
    m.add_argument('--iface', default=None)
    r = sub.add_parser('raw', help='Manual ARP frame using Linux raw socket')
    r.add_argument('--iface', required=True)
    r.add_argument('--source-ip', required=True)
    r.add_argument('--target-ip', required=True)
    r.add_argument('--source-mac', required=True)
    sub.add_parser('demo', help='Offline change detection demonstration')
    a = p.parse_args()
    try:
        if a.command == 'scan':
            hosts = local_scan(a.network)
            print_hosts(hosts)
            plot_hosts(hosts, a.graph)
        elif a.command == 'monitor':
            monitor(a.seconds, a.iface)
        elif a.command == 'raw':
            raw_arp_request(a.iface, a.source_ip, a.target_ip, a.source_mac)
        else:
            demo_detection()
    except (OSError, PermissionError, ImportError, ValueError) as e:
        p.exit(1, f'Error: {e}\n')


if __name__ == '__main__':
    main()
