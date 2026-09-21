from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev

import pandas as pd
from scapy.all import PcapReader
from scapy.layers.inet import IP


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    index = (len(ordered) - 1) * quantile
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


def extract_flow_features(pcap_path: str | Path) -> pd.DataFrame:
    flows: dict[tuple[int, str, str], list[dict[str, float]]] = defaultdict(list)
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            if IP not in packet or packet[IP].proto != 50:
                continue
            payload = bytes(packet[IP].payload)
            if len(payload) < 8:
                continue
            spi = int.from_bytes(payload[:4], "big")
            key = (spi, packet[IP].src, packet[IP].dst)
            flows[key].append(
                {
                    "timestamp": float(packet.time),
                    "size": float(len(bytes(packet[IP]))),
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                }
            )
    rows: list[dict[str, float | str | int]] = []
    for (spi, src, dst), packets in flows.items():
        sizes = [entry["size"] for entry in packets]
        timestamps = [entry["timestamp"] for entry in packets]
        iats = [
            max(timestamps[idx] - timestamps[idx - 1], 0.0) for idx in range(1, len(timestamps))
        ]
        size_mean = mean(sizes) if sizes else 0.0
        size_std = pstdev(sizes) if len(sizes) > 1 else 0.0
        iat_mean = mean(iats) if iats else 0.0
        iat_std = pstdev(iats) if len(iats) > 1 else 0.0
        bursts = 1
        burst_lengths = []
        current_burst = 1
        for iat in iats:
            if iat <= max(iat_mean * 1.5, 0.03):
                current_burst += 1
            else:
                burst_lengths.append(current_burst)
                current_burst = 1
                bursts += 1
        burst_lengths.append(current_burst)
        size_mod_4 = mean([1.0 if size % 4 == 0 else 0.0 for size in sizes]) if sizes else 0.0
        size_mod_8 = mean([1.0 if size % 8 == 0 else 0.0 for size in sizes]) if sizes else 0.0
        size_mod_16 = mean([1.0 if size % 16 == 0 else 0.0 for size in sizes]) if sizes else 0.0
        overhead_consistency = 1.0 - min(size_std / max(size_mean, 1.0), 1.0)
        rows.append(
            {
                "spi": spi,
                "src": src,
                "dst": dst,
                "packet_count": len(sizes),
                "duration": max(timestamps[-1] - timestamps[0], 0.0)
                if len(timestamps) > 1
                else 0.0,
                "size_mean": size_mean,
                "size_std": size_std,
                "size_p10": _percentile(sizes, 0.10),
                "size_p50": _percentile(sizes, 0.50),
                "size_p90": _percentile(sizes, 0.90),
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "iat_cv": iat_std / iat_mean if iat_mean else 0.0,
                "burst_count": bursts,
                "burst_mean_length": mean(burst_lengths) if burst_lengths else 0.0,
                "byte_direction_ratio": 1.0,
                "overhead_consistency": overhead_consistency,
                "size_mod_4_ratio": size_mod_4,
                "size_mod_8_ratio": size_mod_8,
                "size_mod_16_ratio": size_mod_16,
            }
        )
    return pd.DataFrame(rows)
