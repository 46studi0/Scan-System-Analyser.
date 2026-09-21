"""
capture.py - Пакетный (не live) захват трафика через scapy.

Захватывает пакеты в течение фиксированного времени и сохраняет их
в pcap-файл, плюс CSV с метаданными по каждому пакету для анализа.

Требует прав root/администратора.
"""
import argparse
import csv
import sys

try:
    from scapy.all import sniff, wrpcap, IP, TCP, UDP
except ImportError:
    print("Нужен scapy. Установите: pip install scapy", file=sys.stderr)
    sys.exit(1)


def packet_to_row(pkt):
    if IP not in pkt:
        return None
    proto = "OTHER"
    sport = dport = None
    if TCP in pkt:
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport

    return {
        "timestamp": pkt.time,
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "proto": proto,
        "src_port": sport,
        "dst_port": dport,
        "length": len(pkt),
    }


def run_capture(iface: str, duration: int, pcap_out: str, csv_out: str, bpf_filter: str = None):
    print(f"[*] Захват на {iface} в течение {duration}с ... (нужен root)")
    packets = sniff(iface=iface, timeout=duration, filter=bpf_filter)
    print(f"[+] Захвачено {len(packets)} пакетов")

    wrpcap(pcap_out, packets)
    print(f"[+] Сырые пакеты сохранены в {pcap_out}")

    rows = [r for r in (packet_to_row(p) for p in packets) if r]
    if rows:
        with open(csv_out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] Метаданные потоков сохранены в {csv_out} ({len(rows)} строк)")
    else:
        print("[!] IP-пакеты не захвачены; CSV не создан")

    return rows


def main():
    ap = argparse.ArgumentParser(description="Пакетный захват трафика (scapy)")
    ap.add_argument("--iface", required=True, help="Сетевой интерфейс, напр. eth0, en0")
    ap.add_argument("--duration", type=int, default=60, help="Длительность захвата в секундах")
    ap.add_argument("--pcap-out", default="capture.pcap")
    ap.add_argument("--csv-out", default="capture.csv")
    ap.add_argument("--filter", default=None, help="BPF-фильтр, напр. 'tcp or udp'")
    args = ap.parse_args()

    run_capture(args.iface, args.duration, args.pcap_out, args.csv_out, args.filter)


if __name__ == "__main__":
    main()
