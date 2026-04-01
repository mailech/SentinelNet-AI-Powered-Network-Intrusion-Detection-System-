from scapy.all import sniff, TCP, UDP, IP
import threading
import time

live_stats = {
    "packets": 0,
    "src_bytes": 0,
    "dst_bytes": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "other_count": 0,
    "sniffer_error": None
}

packet_records = []
flow_tracker = {}

lock = threading.Lock()


def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        with lock:
            live_stats["packets"] += 1
            pkt_len = len(packet)

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            protocol_name = "other"
            src_port = 0
            dst_port = 0
            flags = ""

            if packet.haslayer(TCP):
                protocol_name = "tcp"
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                flags = str(tcp_layer.flags)
                live_stats["tcp_count"] += 1

            elif packet.haslayer(UDP):
                protocol_name = "udp"
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                live_stats["udp_count"] += 1

            else:
                live_stats["other_count"] += 1

            now = time.time()

            live_stats["src_bytes"] += pkt_len
            live_stats["dst_bytes"] += pkt_len

            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol_name)

            if flow_key not in flow_tracker:
                flow_tracker[flow_key] = {
                    "first_seen": now,
                    "last_seen": now,
                    "packet_count": 0,
                    "byte_count": 0
                }

            flow_tracker[flow_key]["last_seen"] = now
            flow_tracker[flow_key]["packet_count"] += 1
            flow_tracker[flow_key]["byte_count"] += pkt_len

            duration = max(
                1,
                int(flow_tracker[flow_key]["last_seen"] - flow_tracker[flow_key]["first_seen"])
            )

            record = {
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol_type": protocol_name,
                "packet_len": pkt_len,
                "duration": duration,
                "src_bytes": flow_tracker[flow_key]["byte_count"],
                "dst_bytes": pkt_len,
                "count": flow_tracker[flow_key]["packet_count"],
                "srv_count": flow_tracker[flow_key]["packet_count"],
                "tcp_count": 1 if protocol_name == "tcp" else 0,
                "udp_count": 1 if protocol_name == "udp" else 0,
                "other_count": 1 if protocol_name == "other" else 0,
                "flag_syn": 1 if "S" in flags else 0,
                "flag_ack": 1 if "A" in flags else 0,
                "flag_fin": 1 if "F" in flags else 0,
                "flag_rst": 1 if "R" in flags else 0
            }

            packet_records.append(record)

            if len(packet_records) > 400:
                del packet_records[:-400]

            old_keys = []
            for key, value in flow_tracker.items():
                if now - value["last_seen"] > 60:
                    old_keys.append(key)

            for key in old_keys:
                del flow_tracker[key]

    except Exception as e:
        with lock:
            live_stats["sniffer_error"] = str(e)
        print("Packet processing error:", e)


def start_sniffing(interface=None):
    try:
        sniff(prn=process_packet, store=False, iface=interface)
    except Exception as e:
        with lock:
            live_stats["sniffer_error"] = str(e)
        print("Sniffer error:", e)