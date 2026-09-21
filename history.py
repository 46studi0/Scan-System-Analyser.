"""
history.py - Хранение истории появления устройств в сети (SQLite).

Каждый запуск scanner.run_scan() может записывать найденные хосты сюда.
Позволяет отвечать на вопрос "кто и когда подключался к сети", а не
только "кто подключён прямо сейчас".

Ограничение: история строится только вперёд с момента, когда вы начали
использовать этот модуль. Прошлые подключения, случившиеся до первого
запуска, инструмент восстановить не может.
"""
import sqlite3
import time
from datetime import datetime, timedelta

DEFAULT_DB = "netsentry.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    vendor TEXT,
    open_ports TEXT,
    timestamp REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sightings_mac ON sightings(mac);
CREATE INDEX IF NOT EXISTS idx_sightings_timestamp ON sightings(timestamp);
"""


def init_db(db_path: str = DEFAULT_DB):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    # Миграция: если база создана до появления колонки vendor, добавляем её.
    try:
        conn.execute("ALTER TABLE sightings ADD COLUMN vendor TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # колонка уже существует
    conn.commit()
    return conn


def record_scan(hosts: list, db_path: str = DEFAULT_DB):
    """Сохраняет результаты одного скана (список хостов) в базу."""
    conn = init_db(db_path)
    now = time.time()
    rows = [
        (h["mac"], h["ip"], h.get("vendor", "неизвестно"), ",".join(str(p) for p in h.get("open_ports", [])), now)
        for h in hosts
    ]
    conn.executemany(
        "INSERT INTO sightings (mac, ip, vendor, open_ports, timestamp) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()


def get_device_history(db_path: str = DEFAULT_DB, days: int = None):
    """Возвращает сводку по каждому MAC: первое/последнее появление за ВСЮ
    историю, сколько раз замечен всего, последний известный IP.

    Если задан `days`, отбираются только устройства, которые были активны
    в это окно (т.е. имеют хотя бы одну запись не старше `days` дней) —
    но first_seen/last_seen/times_seen всё равно считаются по полной
    истории устройства, а не только по этому окну. Иначе "впервые"
    выглядело бы так, будто устройство появилось только что, даже если
    оно на самом деле в сети уже давно.
    """
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row

    query = """
        SELECT
            mac,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen,
            COUNT(*) AS times_seen,
            (SELECT ip FROM sightings s2
             WHERE s2.mac = s1.mac
             ORDER BY timestamp DESC LIMIT 1) AS last_ip,
            (SELECT vendor FROM sightings s3
             WHERE s3.mac = s1.mac AND vendor IS NOT NULL
             ORDER BY timestamp DESC LIMIT 1) AS vendor
        FROM sightings s1
    """
    params = ()
    if days is not None:
        cutoff = time.time() - days * 86400
        query += """
            WHERE mac IN (
                SELECT DISTINCT mac FROM sightings WHERE timestamp >= ?
            )
        """
        params = (cutoff,)
    query += " GROUP BY mac ORDER BY last_seen DESC"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_known_macs(db_path: str = DEFAULT_DB) -> set:
    """Возвращает множество всех MAC-адресов, когда-либо встреченных в базе
    (используется, чтобы отличить реально новое устройство от уже известного)."""
    conn = init_db(db_path)
    rows = conn.execute("SELECT DISTINCT mac FROM sightings").fetchall()
    conn.close()
    return {r[0] for r in rows}


def get_new_devices(db_path: str = DEFAULT_DB, since_hours: int = 24):
    """Возвращает устройства, впервые замеченные за последние `since_hours` часов."""
    all_devices = get_device_history(db_path)
    cutoff = time.time() - since_hours * 3600
    return [d for d in all_devices if d["first_seen"] >= cutoff]


def format_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def print_history(db_path: str = DEFAULT_DB, days: int = None):
    devices = get_device_history(db_path, days)
    if not devices:
        print("[!] История пуста — ещё не было ни одного скана с записью в базу.")
        return

    print(f"{'MAC':<20}{'Последний IP':<16}{'Устройство':<28}{'Впервые':<20}{'Последний раз':<20}{'Раз замечен':<12}")
    print("-" * 116)
    for d in devices:
        vendor = (d.get("vendor") or "неизвестно")[:26]
        print(
            f"{d['mac']:<20}{d['last_ip']:<16}{vendor:<28}"
            f"{format_timestamp(d['first_seen']):<20}"
            f"{format_timestamp(d['last_seen']):<20}"
            f"{d['times_seen']:<12}"
        )
