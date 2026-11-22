"""Write a small, synthetic PCAP for the offline analysis exercise."""

import argparse
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, Ether, wrpcap


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("输出文件已存在，请选择新文件名。")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    link = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    network = IP(src="192.0.2.1", dst="192.0.2.2", ttl=42)
    packets = [
        link / network / TCP(sport=49800, dport=443, flags="S", seq=7),
        link / network / UDP(sport=50000, dport=9999),
        link / network / ICMP(type=8, id=10),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index
    wrpcap(str(args.output), packets)
    print("已写入 3 个合成报文。")


if __name__ == "__main__":
    main()
