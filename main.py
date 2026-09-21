"""
main.py - Точка входа NetSentry CLI.

Использование:
    python main.py scan    --network 192.168.1.0/24 [--ports 1-1024] [--output scan_results.json]
    python main.py capture --iface eth0 [--duration 60] [--pcap-out capture.pcap] [--csv-out capture.csv]
    python main.py analyze --csv capture.csv [--output report.json] [--no-ml]
"""
import argparse

import scanner
import capture
import analyzer
import history


def main():
    ap = argparse.ArgumentParser(prog="netsentry", description="Сканер сети + анализатор аномалий трафика")
    sub = ap.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Найти хосты и открытые порты в сети")
    p_scan.add_argument("--network", required=True)
    p_scan.add_argument("--ports", default=None)
    p_scan.add_argument("--output", default="scan_results.json")
    p_scan.add_argument("--db", default=None, help="Путь к файлу истории SQLite; если указан, результаты сохраняются и туда")
    p_scan.add_argument("--alert", action="store_true", help="Оповещать (звук + консоль) о по-настоящему новых устройствах (требует --db)")

    p_cap = sub.add_parser("capture", help="Захватить трафик за фиксированное время")
    p_cap.add_argument("--iface", required=True)
    p_cap.add_argument("--duration", type=int, default=60)
    p_cap.add_argument("--pcap-out", default="capture.pcap")
    p_cap.add_argument("--csv-out", default="capture.csv")
    p_cap.add_argument("--filter", default=None)

    p_an = sub.add_parser("analyze", help="Проанализировать захваченный трафик на аномалии")
    p_an.add_argument("--csv", required=True)
    p_an.add_argument("--output", default="report.json")
    p_an.add_argument("--no-ml", action="store_true")

    p_hist = sub.add_parser("history", help="Показать историю устройств, встреченных при сканах")
    p_hist.add_argument("--db", default="netsentry.db", help="Путь к файлу истории SQLite")
    p_hist.add_argument("--days", type=int, default=None, help="Показать только за последние N дней")
    p_hist.add_argument("--new-since-hours", type=int, default=None, help="Показать только устройства, впервые замеченные за последние N часов")

    args = ap.parse_args()

    if args.command == "scan":
        scanner.run_scan(args.network, args.ports, args.output, args.db, args.alert)
    elif args.command == "capture":
        capture.run_capture(args.iface, args.duration, args.pcap_out, args.csv_out, args.filter)
    elif args.command == "analyze":
        analyzer.run_analysis(args.csv, args.output, use_ml=not args.no_ml)
    elif args.command == "history":
        if args.new_since_hours is not None:
            new_devices = history.get_new_devices(args.db, args.new_since_hours)
            if not new_devices:
                print(f"[+] Новых устройств за последние {args.new_since_hours}ч не найдено")
            else:
                print(f"[!] Новые устройства за последние {args.new_since_hours}ч:")
                for d in new_devices:
                    vendor = d.get("vendor") or "неизвестно"
                    print(f"    {d['mac']}  {d['last_ip']}  ({vendor})  впервые: {history.format_timestamp(d['first_seen'])}")
        else:
            history.print_history(args.db, args.days)


if __name__ == "__main__":
    main()
