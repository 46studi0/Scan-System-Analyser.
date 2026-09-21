"""
scanner.py - Обнаружение хостов в локальной сети и сканирование портов.

Находит живые хосты в подсети через ARP-запросы, затем делает
лёгкий TCP connect scan по каждому хосту для поиска открытых портов.

Требует прав root/администратора (raw sockets для ARP).
"""
import argparse
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    print("Нужен scapy. Установите: pip install scapy", file=sys.stderr)
    sys.exit(1)

try:
    from manuf import manuf
    _VENDOR_PARSER = manuf.MacParser()
except ImportError:
    _VENDOR_PARSER = None

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 3306, 5432, 8080, 8443]


def lookup_vendor(mac: str) -> str:
    """Определяет производителя устройства по MAC-адресу (офлайн, база OUI)."""
    if _VENDOR_PARSER is None:
        return "неизвестно (нужен pip install manuf)"
    vendor = _VENDOR_PARSER.get_manuf_long(mac) or _VENDOR_PARSER.get_manuf(mac)
    return vendor or "неизвестно"


def arp_scan(network: str, timeout: int = 3):
    """Рассылает ARP-запросы по всей подсети и собирает ответы."""
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(packet, timeout=timeout, verbose=False)

    hosts = []
    for _, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})
    return hosts


def scan_port(ip: str, port: int, timeout: float = 0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return port if result == 0 else None
    finally:
        sock.close()


def port_scan(ip: str, ports=None, max_workers: int = 50):
    ports = ports or COMMON_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_port, ip, p): p for p in ports}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports)


def parse_port_range(spec: str):
    if "-" in spec:
        start, end = spec.split("-")
        return list(range(int(start), int(end) + 1))
    return [int(p) for p in spec.split(",")]


def run_scan(network: str, port_spec: str = None, output: str = None, db_path: str = None, alert: bool = False):
    print(f"[*] ARP-скан {network} ... (нужен root)")
    hosts = arp_scan(network)
    print(f"[+] Найдено {len(hosts)} живых хостов")

    ports = parse_port_range(port_spec) if port_spec else COMMON_PORTS

    results = []
    for host in hosts:
        print(f"[*] Сканирую порты {host['ip']} ...")
        t0 = time.time()
        open_ports = port_scan(host["ip"], ports)
        elapsed = round(time.time() - t0, 2)
        vendor = lookup_vendor(host["mac"])
        entry = {
            "ip": host["ip"],
            "mac": host["mac"],
            "vendor": vendor,
            "open_ports": open_ports,
            "scan_time_s": elapsed,
            "timestamp": time.time(),
        }
        results.append(entry)
        print(f"    -> устройство: {vendor}")
        print(f"    -> открытые порты: {open_ports if open_ports else 'не найдено'}")

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Результаты сохранены в {output}")

    if db_path:
        import history

        known_macs = history.get_known_macs(db_path) if alert else set()

        history.record_scan(results, db_path)
        print(f"[+] Результаты записаны в историю ({db_path})")

        if alert:
            import alerts
            new_devices = [r for r in results if r["mac"] not in known_macs]
            for entry in new_devices:
                alerts.notify_new_device(entry["mac"], entry["ip"], entry.get("vendor", "неизвестно"))
            if not new_devices:
                print("[*] Новых устройств не обнаружено")

    return results


def main():
    ap = argparse.ArgumentParser(description="Сканер локальной сети + портов")
    ap.add_argument("--network", required=True, help="CIDR сети, напр. 192.168.1.0/24")
    ap.add_argument("--ports", default=None, help="Диапазон/список портов, напр. 1-1024 или 22,80,443")
    ap.add_argument("--output", default="scan_results.json", help="Файл вывода JSON")
    ap.add_argument("--db", default=None, help="Путь к файлу истории SQLite (напр. netsentry.db); если указан, результаты также сохраняются туда")
    ap.add_argument("--alert", action="store_true", help="Оповещать (звук + консоль) о по-настоящему новых устройствах (требует --db)")
    args = ap.parse_args()

    try:
        ipaddress.ip_network(args.network, strict=False)
    except ValueError:
        print("Некорректный CIDR сети", file=sys.stderr)
        sys.exit(1)

    run_scan(args.network, args.ports, args.output, args.db, args.alert)


if __name__ == "__main__":
    main()
