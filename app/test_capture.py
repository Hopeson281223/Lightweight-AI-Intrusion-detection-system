from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, deque
import numpy as np
import time
import requests
import joblib
import os
from pathlib import Path

# ---------------- CONFIG ----------------
MODEL_PATH = Path("models/decision_tree_cic_model.joblib")
API_URL = "http://127.0.0.1:8000/predict"  # FastAPI endpoint
DATASET_NAME = "cic"  # must match your trained dataset name
MAX_FLOW_AGE = 5  # seconds

# ---------------- FEATURE NAMES ----------------
LIVE_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Average Packet Size", "Fwd Header Length", "Bwd Header Length", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "Down/Up Ratio", "Subflow Fwd Packets", "Subflow Bwd Packets", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd"
]

# ---------------- FLOW STORAGE ----------------
flows = defaultdict(lambda: {
    "timestamps": deque(),
    "fwd_lengths": deque(),
    "bwd_lengths": deque(),
    "fwd_flags": defaultdict(int),
    "bwd_flags": defaultdict(int),
    "fwd_headers": deque(),
    "bwd_headers": deque(),
    "init_win_fwd": None,
    "init_win_bwd": None,
    "act_data_pkt_fwd": 0
})

# ---------------- MODEL LOAD ----------------
model = None
if MODEL_PATH.exists():
    try:
        model = joblib.load(MODEL_PATH)
        print("[INFO] Model loaded from disk.")
    except Exception as e:
        print(f"[WARN] Could not load model ({e}). Falling back to API mode.")
else:
    print("[WARN] No local model found. Using FastAPI endpoint for predictions.")

# ---------------- FEATURE EXTRACTION ----------------
def extract_features(flow, dst_port):
    fwd = np.array(flow["fwd_lengths"]) if flow["fwd_lengths"] else np.array([0])
    bwd = np.array(flow["bwd_lengths"]) if flow["bwd_lengths"] else np.array([0])
    ts = np.array(flow["timestamps"]) if flow["timestamps"] else np.array([0])
    fwd_hdr = np.array(flow["fwd_headers"]) if flow["fwd_headers"] else np.array([0])
    bwd_hdr = np.array(flow["bwd_headers"]) if flow["bwd_headers"] else np.array([0])

    total_bytes = fwd.sum() + bwd.sum()
    duration = ts[-1] - ts[0] if len(ts) > 1 else 0
    flow_bytes_s = total_bytes / (duration + 1e-6)
    flow_pkts_s = (len(fwd) + len(bwd)) / (duration + 1e-6)
    iat = np.diff(ts) if len(ts) > 1 else np.array([0])
    down_up_ratio = bwd.sum() / (fwd.sum() + 1e-6)

    features = [
        dst_port, duration, len(fwd), len(bwd), fwd.sum(), bwd.sum(),
        fwd.max(), fwd.min(), fwd.mean(), fwd.std(),
        bwd.max(), bwd.min(), bwd.mean(), bwd.std(),
        flow_bytes_s, flow_pkts_s, iat.mean(), iat.std(), iat.max(), iat.min(),
        flow["fwd_flags"]["PSH"], flow["bwd_flags"]["PSH"],
        flow["fwd_flags"]["URG"], flow["bwd_flags"]["URG"],
        flow["fwd_flags"]["FIN"], flow["fwd_flags"]["SYN"], flow["fwd_flags"]["RST"],
        flow["fwd_flags"]["PSH"] + flow["bwd_flags"]["PSH"],
        flow["fwd_flags"]["ACK"] + flow["bwd_flags"]["ACK"],
        flow["fwd_flags"]["URG"] + flow["bwd_flags"]["URG"],
        flow["fwd_flags"].get("CWE", 0) + flow["bwd_flags"].get("CWE", 0),
        flow["fwd_flags"].get("ECE", 0) + flow["bwd_flags"].get("ECE", 0),
        (fwd.sum() + bwd.sum()) / (len(fwd) + len(bwd) + 1e-6),
        fwd_hdr.mean(), bwd_hdr.mean(),
        fwd.min(), fwd.max(),
        np.mean(np.concatenate([fwd, bwd])),
        np.std(np.concatenate([fwd, bwd])),
        np.var(np.concatenate([fwd, bwd])),
        down_up_ratio,
        len(fwd), len(bwd),
        flow["init_win_fwd"] or 0,
        flow["init_win_bwd"] or 0,
        flow["act_data_pkt_fwd"]
    ]
    return [float(x) for x in features]

# ---------------- FLOW FLUSH ----------------
def flush_old_flows():
    now = time.time()
    to_delete = [k for k, f in flows.items() if f["timestamps"] and now - f["timestamps"][-1] > MAX_FLOW_AGE]
    for k in to_delete:
        features = extract_features(flows[k], k[3])
        src, dst = k[0], k[1]

        # Show flow summary
        print(f"\n[FLOW ENDED]\nSource: {src} -> Dest: {dst} | Port: {k[3]}")
        print(f"Features: {features[:10]} ...")

        # Predict locally or via FastAPI
        try:
            if model:
                pred = model.predict([features])[0]
                label = getattr(model, "classes_", [None])[int(pred)] if hasattr(model, "classes_") else pred
                print(f"Prediction: {label}")
            else:
                resp = requests.post(API_URL, json={"dataset": DATASET_NAME, "features": features})
                if resp.status_code == 200:
                    result = resp.json()
                    print(f"Prediction: {result.get('label')} (Confidence: {result.get('confidence')})")
                else:
                    print(f"[ERROR] API prediction failed: {resp.text}")
        except Exception as e:
            print(f"[ERROR] Prediction failed: {e}")

        del flows[k]

# ---------------- PACKET PROCESSING ----------------
def process_packet(pkt):
    if IP not in pkt:
        return

    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
    if proto == "OTHER":
        return

    src, dst = pkt[IP].src, pkt[IP].dst
    sport, dport = getattr(pkt, "sport", 0), getattr(pkt, "dport", 0)
    key = (src, dst, sport, dport, proto)
    rev_key = (dst, src, dport, sport, proto)
    now = time.time()

    if TCP in pkt:
        flags = pkt[TCP].flags
        flows[key]["init_win_fwd"] = flows[key]["init_win_fwd"] or pkt[TCP].window
        flows[rev_key]["init_win_bwd"] = flows[rev_key]["init_win_bwd"] or pkt[TCP].window
        flows[key]["act_data_pkt_fwd"] += 1
        flows[key]["fwd_flags"]["SYN"] += int(flags & 0x02 != 0)
        flows[key]["fwd_flags"]["ACK"] += int(flags & 0x10 != 0)
        flows[key]["fwd_flags"]["FIN"] += int(flags & 0x01 != 0)
        flows[key]["fwd_flags"]["PSH"] += int(flags & 0x08 != 0)
        flows[key]["fwd_flags"]["URG"] += int(flags & 0x20 != 0)
        flows[key]["fwd_flags"]["ECE"] += int(flags & 0x40 != 0)
        flows[key]["fwd_flags"]["CWE"] += int(flags & 0x80 != 0)

    pkt_len = len(pkt)
    header_len = pkt[IP].ihl * 4 + (pkt[TCP].dataofs * 4 if TCP in pkt else 0)
    flows[key]["timestamps"].append(now)
    flows[key]["fwd_lengths"].append(pkt_len)
    flows[key]["fwd_headers"].append(header_len)

    flush_old_flows()

# ---------------- MAIN ----------------
if __name__ == "__main__":
    print("[INFO] Starting live capture. Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)
