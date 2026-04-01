import pandas as pd
from sniffer import live_stats, lock, packet_records


def build_live_feature_row(max_rows=25):
    with lock:
        sniffer_error = live_stats.get("sniffer_error")

        rows = packet_records[-max_rows:].copy()
        packet_records.clear()

        live_stats["packets"] = 0
        live_stats["src_bytes"] = 0
        live_stats["dst_bytes"] = 0
        live_stats["tcp_count"] = 0
        live_stats["udp_count"] = 0
        live_stats["other_count"] = 0

    if not rows:
        df = pd.DataFrame(columns=[
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol_type", "packet_len", "duration", "src_bytes", "dst_bytes",
            "count", "srv_count", "tcp_count", "udp_count", "other_count",
            "flag_syn", "flag_ack", "flag_fin", "flag_rst"
        ])
        return df, sniffer_error

    df = pd.DataFrame(rows)

    required_cols = [
        "duration",
        "src_bytes",
        "dst_bytes",
        "count",
        "srv_count",
        "tcp_count",
        "udp_count",
        "other_count",
        "flag_syn",
        "flag_ack",
        "flag_fin",
        "flag_rst",
        "packet_len",
        "src_port",
        "dst_port"
    ]

    for col in required_cols:
        if col not in df.columns:
            df[col] = 0

    return df, sniffer_error