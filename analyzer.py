"""
analyzer.py - Детект аномалий на уровне потоков (flows).

Читает CSV, созданный capture.py, строит агрегированные фичи по
потокам и источникам, затем помечает аномалии через:
  1. Эвристики (порт-скан / скан сети / аномально большая передача)
  2. Статистические выбросы (z-score по числу пакетов/байт)
  3. Опционально ML (IsolationForest)
"""
import argparse
import json
import sys

import pandas as pd
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    HAVE_SKLEARN = True
except ImportError:
    HAVE_SKLEARN = False


PORT_SCAN_THRESHOLD = 15      # уникальных dst-портов от одного src -> подозрение на порт-скан
NETWORK_SCAN_THRESHOLD = 25   # уникальных dst-IP от одного src -> подозрение на скан сети
ZSCORE_THRESHOLD = 3.0


def load_flows(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    return df.dropna(subset=["timestamp"])


def build_flow_table(df: pd.DataFrame) -> pd.DataFrame:
    """Агрегирует пакеты в потоки по ключу (src, dst, dst_port, proto)."""
    grouped = df.groupby(["src_ip", "dst_ip", "dst_port", "proto"], dropna=False)
    flows = grouped.agg(
        packet_count=("length", "count"),
        total_bytes=("length", "sum"),
        start_time=("timestamp", "min"),
        end_time=("timestamp", "max"),
    ).reset_index()
    flows["duration_s"] = (flows["end_time"] - flows["start_time"]).clip(lower=0.001)
    flows["bytes_per_sec"] = flows["total_bytes"] / flows["duration_s"]
    flows["avg_packet_size"] = flows["total_bytes"] / flows["packet_count"]
    return flows


def detect_scan_behavior(df: pd.DataFrame) -> list:
    """Помечает src-IP, которые обратились к аномально большому числу
    уникальных dst-портов или dst-IP (классическая сигнатура скана)."""
    findings = []
    per_src = df.groupby("src_ip")
    for src_ip, group in per_src:
        distinct_ports = group["dst_port"].nunique()
        distinct_hosts = group["dst_ip"].nunique()

        if distinct_ports >= PORT_SCAN_THRESHOLD:
            findings.append({
                "type": "port_scan_suspected",
                "src_ip": src_ip,
                "distinct_dst_ports": int(distinct_ports),
                "severity": "high" if distinct_ports > PORT_SCAN_THRESHOLD * 2 else "medium",
            })
        if distinct_hosts >= NETWORK_SCAN_THRESHOLD:
            findings.append({
                "type": "network_scan_suspected",
                "src_ip": src_ip,
                "distinct_dst_ips": int(distinct_hosts),
                "severity": "high" if distinct_hosts > NETWORK_SCAN_THRESHOLD * 2 else "medium",
            })
    return findings


def detect_statistical_outliers(flows: pd.DataFrame) -> list:
    """Помечает потоки, у которых число байт/пакетов - статистический
    выброс (z-score выше порога) относительно всех потоков."""
    findings = []
    for col in ["total_bytes", "packet_count", "bytes_per_sec"]:
        mean, std = flows[col].mean(), flows[col].std()
        if std == 0 or np.isnan(std):
            continue
        z = (flows[col] - mean) / std
        outliers = flows[z.abs() >= ZSCORE_THRESHOLD]
        for _, row in outliers.iterrows():
            dst_port = row["dst_port"]
            findings.append({
                "type": f"statistical_outlier_{col}",
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "dst_port": int(dst_port) if pd.notna(dst_port) else None,
                "value": float(row[col]),
                "z_score": round(float(z.loc[row.name]), 2),
            })
    return findings


def detect_ml_outliers(flows: pd.DataFrame, contamination: float = 0.05) -> list:
    """Опционально: IsolationForest по числовым фичам потоков."""
    if not HAVE_SKLEARN or len(flows) < 10:
        return []

    features = flows[["packet_count", "total_bytes", "duration_s", "bytes_per_sec", "avg_packet_size"]].fillna(0)
    model = IsolationForest(contamination=contamination, random_state=42)
    preds = model.fit_predict(features)
    scores = model.decision_function(features)

    findings = []
    for i, pred in enumerate(preds):
        if pred == -1:
            row = flows.iloc[i]
            dst_port = row["dst_port"]
            findings.append({
                "type": "ml_outlier",
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "dst_port": int(dst_port) if pd.notna(dst_port) else None,
                "anomaly_score": round(float(scores[i]), 4),
            })
    return findings


def run_analysis(csv_path: str, output: str = None, use_ml: bool = True):
    df = load_flows(csv_path)
    flows = build_flow_table(df)

    print(f"[*] Загружено {len(df)} пакетов -> {len(flows)} потоков")

    findings = []
    findings += detect_scan_behavior(df)
    findings += detect_statistical_outliers(flows)
    if use_ml:
        findings += detect_ml_outliers(flows)

    report = {
        "packet_count": int(len(df)),
        "flow_count": int(len(flows)),
        "finding_count": len(findings),
        "findings": findings,
    }

    print(f"[+] Найдено {len(findings)} потенциальных аномалий")
    for f in findings:
        print(f"    - {f['type']}: {f}")

    if output:
        with open(output, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] Отчёт сохранён в {output}")

    return report


def main():
    ap = argparse.ArgumentParser(description="Анализатор аномалий трафика по потокам")
    ap.add_argument("--csv", required=True, help="CSV потоков, созданный capture.py")
    ap.add_argument("--output", default="report.json")
    ap.add_argument("--no-ml", action="store_true", help="Отключить шаг IsolationForest")
    args = ap.parse_args()

    run_analysis(args.csv, args.output, use_ml=not args.no_ml)


if __name__ == "__main__":
    main()
