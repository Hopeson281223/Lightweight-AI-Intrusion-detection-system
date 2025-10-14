import threading
import time
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP
from scapy.packet import Packet
import requests
import json
import platform
from datetime import datetime
import numpy as np
import sqlite3
from app.ml.preprocess import LIVE_FEATURES
from app.storage.db import get_db  

class LivePacketCapture:
    def __init__(self, model_endpoint="http://localhost:8000/predict"):
        self.model_endpoint = model_endpoint
        self.capture_thread = None
        self.is_capturing = False
        self.packet_count = 0
        self.current_interface = r"\Device\NPF_{662136C5-DAF0-45FA-AFF8-1889200C99C2}"
        self.last_error = None
        
        # Flow tracking
        self.flows = defaultdict(lambda: {
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
        self.MAX_FLOW_AGE = 5  # seconds

    def list_available_interfaces(self):
        """Return all usable network interfaces (including loopback if active)."""
        try:
            from scapy.arch.windows import get_windows_if_list
            import psutil  # For checking active interface
            win_ifs = get_windows_if_list()
            interfaces = []

            # Get active NICs from psutil (with traffic)
            active_ifaces = set()
            for name, addrs in psutil.net_if_addrs().items():
                stats = psutil.net_if_stats().get(name)
                if stats and stats.isup:
                    active_ifaces.add(name)

            for iface in win_ifs:
                desc = iface.get("description", "").lower()
                name = iface.get("name", "Unknown")

                # Exclude only truly virtual drivers
                if any(bad in desc for bad in ["filter", "scheduler", "miniport", "direct", "virtualbox", "vmware"]):
                    continue

                # Mark as active if it's currently in use
                is_active = name in active_ifaces

                interfaces.append({
                    "name": name,
                    "description": iface.get("description", ""),
                    "device": f"\\Device\\NPF_{iface.get('guid', '')}",
                    "active": is_active
                })

            if not interfaces:
                interfaces = [{"name": "No valid interfaces found", "device": "none", "active": False}]

            # Sort so active interfaces appear first
            interfaces.sort(key=lambda x: not x["active"])
            return interfaces

        except Exception as e:
            print(f"Interface listing error: {e}")
            return [{"name": "Error listing interfaces", "device": "none", "active": False}]

    def set_interface(self, interface_name):
        if not self.is_capturing:
            self.current_interface = interface_name
            print(f"Interface set to: {interface_name}")
            return True
        self.last_error = "Cannot change interface while capturing"
        return False

    
    def extract_flow_features(self, flow, dst_port):
        """Extract features from completed flow"""
        try:
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
        except Exception as e:
            print(f"Flow feature extraction error: {e}")
            return None
    
    def flush_old_flows(self):
        """Flush completed flows for analysis"""
        now = time.time()
        to_delete = []
        
        # First collects all flows to process
        for key, flow in list(self.flows.items()):  # Uses list() to avoid modification during iteration
            if flow["timestamps"] and now - flow["timestamps"][-1] > self.MAX_FLOW_AGE:
                to_delete.append((key, flow.copy()))  # Stores a copy of the flow data
        
        # Then processes and deletes them
        for key, flow_data in to_delete:
            if key not in self.flows:
                continue

            features = self.extract_flow_features(flow_data, key[3])
            src, dst = key[0], key[1]

            if features:
                print(f"Flow completed: {src} -> {dst}:{key[3]} (Packets: {len(flow_data['timestamps'])})")

                # Save to database
                packet_id = self.save_flow_to_database(key, flow_data, features)
                if packet_id:
                    self.send_prediction(features, packet_id, key)

            if key in self.flows:
                del self.flows[key]

    
    def save_flow_to_database(self, flow_key, flow_data, features):
        """Save flow to database using your existing db connection"""
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO packets (ts, src_ip, dst_ip, src_port, dst_port, protocol, length, features_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                flow_key[0],  # src_ip
                flow_key[1],  # dst_ip
                flow_key[2],  # src_port
                flow_key[3],  # dst_port
                flow_key[4],  # protocol
                sum(flow_data["fwd_lengths"]) + sum(flow_data["bwd_lengths"]),  # total length
                json.dumps(features)
            ))
            packet_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            print(f"Saved flow as packet {packet_id}")
            return packet_id
            
        except Exception as e:
            print(f"Database error: {e}")
            return None
    
    def send_prediction(self, features, packet_id, flow_key):
        """Send features for ML prediction"""
        try:
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            response = requests.post(
                self.model_endpoint,
                json={
                    "dataset": "cic",
                    "features": features,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol
                },
                timeout=3
            )
            if response.status_code == 200:
                result = response.json()
                
                # Save prediction
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO predictions (packet_id, label, score) VALUES (?, ?, ?)",
                    (packet_id, result["label"], result["confidence"])
                )
                
                # Create alert if anomalous
                if result["label"] == "ANOMALOUS" and result["confidence"] > 0.7:
                    cursor.execute(
                        "INSERT INTO alerts (prediction_id, severity, message) VALUES (?, ?, ?)",
                        (cursor.lastrowid, "HIGH", f"Anomalous traffic (conf: {result['confidence']:.2f})")
                    )
                    print(f"ALERT: Anomalous traffic detected!")
                
                conn.commit()
                conn.close()
                
                print(f"{src_ip} → {dst_ip} | {protocol} | {result['label']} (conf: {result['confidence']:.2f})")
                
        except Exception as e:
            print(f"Prediction error: {e}")
    
    def packet_handler(self, packet):
        """Process each packet and add to flows"""
        try:
            self.packet_count += 1
            
            if not packet.haslayer(IP):
                return

            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
            if proto == "OTHER":
                return

            src, dst = packet[IP].src, packet[IP].dst
            sport, dport = getattr(packet, "sport", 0), getattr(packet, "dport", 0)
            key = (src, dst, sport, dport, proto)
            rev_key = (dst, src, dport, sport, proto)
            now = time.time()

            if TCP in packet:
                flags = packet[TCP].flags
                self.flows[key]["init_win_fwd"] = self.flows[key]["init_win_fwd"] or packet[TCP].window
                self.flows[rev_key]["init_win_bwd"] = self.flows[rev_key]["init_win_bwd"] or packet[TCP].window
                self.flows[key]["act_data_pkt_fwd"] += 1
                self.flows[key]["fwd_flags"]["SYN"] += int(flags & 0x02 != 0)
                self.flows[key]["fwd_flags"]["ACK"] += int(flags & 0x10 != 0)
                self.flows[key]["fwd_flags"]["FIN"] += int(flags & 0x01 != 0)
                self.flows[key]["fwd_flags"]["PSH"] += int(flags & 0x08 != 0)
                self.flows[key]["fwd_flags"]["URG"] += int(flags & 0x20 != 0)
                self.flows[key]["fwd_flags"]["ECE"] += int(flags & 0x40 != 0)
                self.flows[key]["fwd_flags"]["CWE"] += int(flags & 0x80 != 0)

            pkt_len = len(packet)
            header_len = packet[IP].ihl * 4 + (packet[TCP].dataofs * 4 if TCP in packet else 0)
            self.flows[key]["timestamps"].append(now)
            self.flows[key]["fwd_lengths"].append(pkt_len)
            self.flows[key]["fwd_headers"].append(header_len)

            # Show live packet info
            print(f"Packet #{self.packet_count}: {src} -> {dst}:{dport}")
            
            # Flush old flows periodically
            if self.packet_count % 10 == 0:
                self.flush_old_flows()
                    
        except Exception as e:
            print(f"Packet handler error: {e}")
    
    def _capture_loop(self):
        """Main capture loop"""
        print(f"Starting FLOW-BASED capture on {self.current_interface}")
        try:
            sniff(
                iface=self.current_interface,
                prn=self.packet_handler,
                store=False,
                filter="ip",
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            print(f"Capture error: {e}")
    
    def start_capture(self, interface=None):
        if self.is_capturing:
            self.last_error = "Capture already running"
            return False

        # Auto-select first active interface if none provided
        if not interface or interface == "auto":
            interfaces = self.list_available_interfaces()
            active_ifs = [i for i in interfaces if i.get("active")]
            if active_ifs:
                self.current_interface = active_ifs[0]["device"]
                print(f"Auto-selected active interface: {active_ifs[0]['name']}")
            else:
                self.last_error = "No active interface found"
                print("❌ No active interface found for capture.")
                return False
        else:
            self.current_interface = interface

        self.is_capturing = True
        self.packet_count = 0
        self.flows.clear()
        self.last_error = None

        # Launch capture in background thread
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()

        print(f"✅ Flow-based packet capture started on {self.current_interface}")
        return True

    
    def stop_capture(self):
        if not self.is_capturing:
            self.last_error = "No capture running"
            return False
            
        self.is_capturing = False
        self.last_error = None
        
        print("Stopping capture immediately (fast mode)...")
        
        flows_count = len(self.flows)
        self.flows.clear()
        
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
        
        print(f"Capture stopped. Total packets: {self.packet_count}, Flows cleared: {flows_count}")
        return True
    
    def get_status(self):
        return {
            "is_capturing": self.is_capturing,
            "packets_captured": self.packet_count,
            "active_flows": len(self.flows),
            "interface": self.current_interface
        }

packet_capture = LivePacketCapture()